package decompengine.web

import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFileKey
import decompengine.project.*
import decompengine.repair.StableRegularFile
import kotlinx.serialization.json.*
import kotlin.test.*

/** Synthetic snapshots and captured byte arrays; no store, listener or browser is opened. */
class WebRevisionSourceDiffTest {
    private val jobId = "a".repeat(32)
    private val text = setOf(ProjectFileRole.BUILD_INPUT, ProjectFileRole.VIEWABLE, ProjectFileRole.ARCHIVE_PAYLOAD)

    private class Side(val path: String, val bytes: ByteArray, val roles: Set<ProjectFileRole>,
        val kind: ProjectContentKind = ProjectContentKind.UTF8_TEXT)

    private fun side(path: String, value: String, roles: Set<ProjectFileRole> = text) = Side(path, value.toByteArray(), roles)

    private class Fixture(val snapshots: Map<Pair<String, String>, WebRevisionSourceSnapshot>, val bodies: Map<Pair<String, String>, ByteArray>) {
        var reads = 0
        /** Metadata the body reader observes; it can differ from the compared capture to emulate a concurrent change. */
        var readerSnapshots: Map<Pair<String, String>, WebRevisionSourceSnapshot> = snapshots
    }

    private fun snapshot(run: String, revision: String, sides: List<Side>): WebRevisionSourceSnapshot {
        val files = sides.map { item ->
            WebRevisionSourceFile(GeneratedFileEvidence(item.path, WebExplorationArtifact.sha256(item.bytes), "fixture",
                roles = item.roles, contentKind = item.kind),
                if (ProjectFileRole.BUILD_INPUT in item.roles) item.bytes.size.toLong() else null)
        }
        val inputs = files.filter { it.committedInput }.sortedBy { it.evidence.path }
        val sha = revisionSourceDigest(inputs.joinToString("") { "${it.evidence.path.length}:${it.evidence.path}:${it.sizeBytes}:${it.evidence.sha256}\n" })
        return WebRevisionSourceSnapshot(WebRevisionSourceReference(jobId, run, revision, sha, "version_$run"),
            WebExplorationArtifact.sha256(run.toByteArray()), "c".repeat(64), files)
    }

    private fun fixture(base: List<Side>, head: List<Side>): Fixture {
        val snapshots = mapOf(("run_1" to "revision_1") to snapshot("run_1", "revision_1", base),
            ("run_2" to "revision_2") to snapshot("run_2", "revision_2", head))
        val bodies = (base.map { ("run_1" to it.path) to it.bytes } + head.map { ("run_2" to it.path) to it.bytes }).toMap()
        return Fixture(snapshots, bodies)
    }

    private fun diffs(fixture: Fixture, maximumEdits: Int = WebRevisionSourceDiffs.MAXIMUM_EDITS) = WebRevisionSourceDiffs(
        { job, run, revision -> assertEquals(jobId, job); fixture.snapshots.getValue(run to revision) },
        { _, run, revision, fileId, metadataVersion ->
            fixture.reads++
            // Same rule as the production reader: a different current observation expires the request.
            val snapshot = fixture.readerSnapshots.getValue(run to revision)
            if (snapshot.metadataVersion != metadataVersion) expiredSourceMetadata()
            val file = resolveRevisionSourceFile(snapshot, fileId)
            val bytes = fixture.bodies.getValue(run to file.evidence.path)
            WebRevisionSourceContent(snapshot, fileId, selectRevisionSourceFile(snapshot, fileId, WebSourceReadPurpose.PREVIEW),
                StableRegularFile(bytes, WebExplorationArtifact.sha256(bytes), LinuxFileIdentity(LinuxFileKey(1, 1), 0x8180, 1000, 1000, 1, 1, true, false, false)))
        }, maximumEdits = maximumEdits)

    private val base = "baseRunId=run_1&baseRevisionId=revision_1"

    private fun items(page: JsonObject) = page.getValue("items").jsonArray.map { it.jsonObject }
    private fun id(entry: JsonObject, side: String) = (entry[side] as? JsonObject)?.getValue("fileId")?.jsonPrimitive?.content
    private fun fileQuery(entry: JsonObject, hunk: Int? = null) = base + listOfNotNull(id(entry, "baseFile")?.let { "&baseFileId=$it" },
        id(entry, "headFile")?.let { "&headFileId=$it" }, hunk?.let { "&hunk=$it" }).joinToString("")

    @Test fun `pure additions removals and trimmed edits obey edit and deadline budgets`() {
        val limit = WebRevisionSourceDiffs.MAXIMUM_EDITS
        for (count in listOf(limit, limit + 1)) {
            val changed = IntArray(count) { it + 10 }
            val pairs = listOf(IntArray(0) to changed, changed to IntArray(0),
                intArrayOf(1) to (intArrayOf(1) + changed),
                (intArrayOf(1) + changed) to intArrayOf(1),
                intArrayOf(1, 2) to (intArrayOf(1) + changed + intArrayOf(2)))
            for ((before, after) in pairs) {
                val ops = revisionLineEdits(before, after, limit) { false }
                if (count == limit) assertEquals(count, assertNotNull(ops).count { it != WebDiffOp.EQUAL })
                else assertNull(ops)
                var calls = 0
                assertNull(revisionLineEdits(before, after, limit) { calls++; true })
                if (count == limit) assertEquals(1, calls, "the fast path must consult the deadline")
            }
        }
    }

    @Test fun `classification names both exact revisions and separates added removed modified renamed and unchanged files`() {
        val fixture = fixture(
            listOf(side("Makefile", "all:\n"), side("src/old.c", "int moved;\n"), side("src/gone.c", "int gone;\n"), side("src/same.c", "int same;\n"),
                side("src/body.c", "int a;\n")),
            listOf(side("Makefile", "all: x\n"), side("src/new.c", "int moved;\n"), side("src/same.c", "int same;\n"), side("src/added.c", "int added;\n"),
                side("src/body.c", "int a;\n")))
        val page = diffs(fixture).summary("owner", jobId, "run_2", "revision_2", base)
        assertEquals("run_1", page.getValue("base").jsonObject.getValue("runId").jsonPrimitive.content)
        assertEquals("revision_2", page.getValue("binding").jsonObject.getValue("revisionId").jsonPrimitive.content)
        assertEquals(fixture.snapshots.getValue("run_1" to "revision_1").reference.sourceSha256, page.getValue("baseSourceSha256").jsonPrimitive.content)
        assertEquals(fixture.snapshots.getValue("run_2" to "revision_2").metadataVersion, page.getValue("metadataVersion").jsonPrimitive.content)
        val statuses = items(page).map { it.getValue("status").jsonPrimitive.content to
            ((it["headFile"] as? JsonObject) ?: it.getValue("baseFile").jsonObject).getValue("displayName").jsonPrimitive.content }
        assertEquals(listOf("modified" to "Makefile", "added" to "src/added.c", "removed" to "src/gone.c", "renamed" to "src/new.c"), statuses)
        val renamed = items(page).single { it.getValue("status").jsonPrimitive.content == "renamed" }
        assertEquals("src/old.c", renamed.getValue("baseFile").jsonObject.getValue("displayName").jsonPrimitive.content)
        assertEquals(mapOf("added" to 1, "removed" to 1, "modified" to 1, "renamed" to 1, "unchanged" to 2),
            page.getValue("counts").jsonObject.mapValues { it.value.jsonPrimitive.int })
        assertEquals(0, fixture.reads, "classification uses recorded digests only")
        // An identical rename never invents a text difference.
        val detail = diffs(fixture).file(jobId, "run_2", "revision_2", fileQuery(renamed))
        assertEquals("identical", detail.getValue("representation").jsonPrimitive.content)
        assertEquals(0, fixture.reads)
    }

    @Test fun `text hunks carry exact line numbers context and honest omitted ranges with a complete patch`() {
        val before = (1..40).joinToString("") { "line $it\n" }
        val after = before.replace("line 5\n", "line five\n").replace("line 37\n", "<script>alert(1)</script>\n") + "tail"
        val fixture = fixture(listOf(side("src/a.c", before)), listOf(side("src/a.c", after)))
        val entry = items(diffs(fixture).summary("owner", jobId, "run_2", "revision_2", base)).single()
        val result = diffs(fixture).file(jobId, "run_2", "revision_2", fileQuery(entry))
        assertEquals("text", result.getValue("representation").jsonPrimitive.content)
        assertEquals(40, result.getValue("baseLines").jsonPrimitive.int); assertEquals(41, result.getValue("headLines").jsonPrimitive.int)
        val hunks = result.getValue("hunks").jsonArray.map { it.jsonObject }
        assertEquals(2, hunks.size); assertEquals(2, result.getValue("totalHunks").jsonPrimitive.int)
        assertEquals(listOf(2, 34), hunks.map { it.getValue("baseStart").jsonPrimitive.int })
        assertEquals(listOf(1, 25), hunks.map { it.getValue("unchangedBefore").jsonPrimitive.int })
        assertEquals(0, result.getValue("unchangedAfter").jsonPrimitive.int)
        val first = hunks[0].getValue("lines").jsonArray.map { it.jsonObject }
        assertEquals(listOf("context", "context", "context", "removed", "added", "context", "context", "context"), first.map { it.getValue("kind").jsonPrimitive.content })
        val added = hunks[1].getValue("lines").jsonArray.map { it.jsonObject }.filter { it.getValue("kind").jsonPrimitive.content == "added" }
        assertEquals(listOf("<script>alert(1)</script>", "tail"), added.map { it.getValue("text").jsonPrimitive.content })
        assertTrue(added.last().getValue("missingFinalNewline").jsonPrimitive.boolean)
        val patch = String(diffs(fixture).patch(jobId, "run_2", "revision_2", fileQuery(entry)).bytes)
        assertTrue(patch.startsWith("--- a/src/a.c\n+++ b/src/a.c\n@@ -2,7 +2,7 @@\n"), patch)
        assertTrue(patch.contains("-line 5\n+line five\n"))
        assertTrue(patch.endsWith("+tail\n\\ No newline at end of file\n"), patch)
        // Applying the patch independently reproduces the head bytes exactly.
        assertEquals(after, applyPatch(before, patch))
    }

    @Test fun `long diffs page by hunk with explicit continuation while long lines are marked truncated`() {
        val before = (1..2_000).joinToString("") { "row $it\n" }
        val after = (1..2_000).joinToString("") { if (it % 50 == 0) "changed $it ${"x".repeat(1_500)}\n" else "row $it\n" }
        val fixture = fixture(listOf(side("src/a.c", before)), listOf(side("src/a.c", after)))
        val entry = items(diffs(fixture).summary("owner", jobId, "run_2", "revision_2", base)).single()
        val pages = mutableListOf<JsonObject>(); var hunk: Int? = 0
        while (hunk != null) {
            val page = diffs(fixture).file(jobId, "run_2", "revision_2", fileQuery(entry, hunk)); pages += page
            hunk = page.getValue("nextHunk").jsonPrimitive.intOrNull
        }
        assertEquals(40, pages.first().getValue("totalHunks").jsonPrimitive.int)
        assertEquals(listOf(20, 20), pages.map { it.getValue("hunks").jsonArray.size })
        val lines = pages.flatMap { page -> page.getValue("hunks").jsonArray.flatMap { it.jsonObject.getValue("lines").jsonArray.map { line -> line.jsonObject } } }
        val long = lines.filter { it.getValue("kind").jsonPrimitive.content == "added" }
        assertEquals(40, long.size)
        assertTrue(long.all { it.getValue("truncated").jsonPrimitive.boolean && it.getValue("text").jsonPrimitive.content.length == 1_000 })
        assertEquals(1_500 + "changed 50 ".length, long.first().getValue("characters").jsonPrimitive.int)
        assertEquals("SOURCE_DIFF_RANGE_INVALID", assertFailsWith<WebAccessDenied> {
            diffs(fixture).file(jobId, "run_2", "revision_2", fileQuery(entry, 40)) }.code)
    }

    @Test fun `binary invalid encodings oversized not viewable and edit budget states are explicit without hunks`() {
        val binary = Side("data.bin", byteArrayOf(0, 1, 2), text, ProjectContentKind.BINARY)
        val binary2 = Side("data.bin", byteArrayOf(0, 1, 3), text, ProjectContentKind.BINARY)
        val invalid = Side("src/bad.c", byteArrayOf(0x66, 0xff.toByte(), 0x0a), text)
        val hidden = side("src/hidden.c", "a\n", setOf(ProjectFileRole.BUILD_INPUT)); val hidden2 = side("src/hidden.c", "b\n", setOf(ProjectFileRole.BUILD_INPUT))
        val large = side("src/large.c", "a".repeat(1_048_577)); val large2 = side("src/large.c", "b".repeat(1_048_577))
        val many = side("src/many.c", (1..100).joinToString("") { "a$it\n" }); val many2 = side("src/many.c", (1..100).joinToString("") { "b$it\n" })
        val fixture = fixture(listOf(binary, invalid, hidden, large, many),
            listOf(binary2, side("src/bad.c", "fine\n"), hidden2, large2, many2))
        val entries = items(diffs(fixture, maximumEdits = 50).summary("owner", jobId, "run_2", "revision_2", base))
            .associateBy { it.getValue("headFile").jsonObject.getValue("displayName").jsonPrimitive.content }
        fun state(path: String) = diffs(fixture, maximumEdits = 50).file(jobId, "run_2", "revision_2", fileQuery(entries.getValue(path))).let {
            Triple(it.getValue("representation").jsonPrimitive.content, it.getValue("fallbackReason").jsonPrimitive.contentOrNull,
                it.getValue("hunks").jsonArray.size)
        }
        assertEquals(Triple("binary", "declared-binary", 0), state("data.bin"))
        assertEquals(Triple("binary", "invalid-utf8", 0), state("src/bad.c"))
        assertEquals(Triple("not-viewable", null, 0), state("src/hidden.c"))
        assertEquals(Triple("too-large", null, 0), state("src/large.c"))
        assertEquals(Triple("budget-exceeded", null, 0), state("src/many.c"))
        assertEquals("SOURCE_DIFF_NOT_TEXT", assertFailsWith<WebAccessDenied> {
            diffs(fixture).patch(jobId, "run_2", "revision_2", fileQuery(entries.getValue("data.bin"))) }.code)
    }

    @Test fun `file pairs outside the classification foreign selectors and forged cursors are refused before body reads`() {
        val fixture = fixture(listOf(side("a.c", "1\n"), side("b.c", "2\n")), listOf(side("a.c", "3\n"), side("b.c", "4\n")))
        val entries = items(diffs(fixture).summary("owner", jobId, "run_2", "revision_2", base))
        val crossed = base + "&baseFileId=${id(entries[0], "baseFile")}&headFileId=${id(entries[1], "headFile")}"
        assertEquals("SOURCE_DIFF_ENTRY_NOT_FOUND", assertFailsWith<WebAccessDenied> { diffs(fixture).file(jobId, "run_2", "revision_2", crossed) }.code)
        for (query in listOf(null, "baseRunId=run_1", "$base&baseFileId=../a.c", "$base&path=a.c", "$base&baseRunId=run_1", base)) {
            assertEquals(422, assertFailsWith<WebAccessDenied> { diffs(fixture).file(jobId, "run_2", "revision_2", query) }.status)
        }
        assertEquals("INVALID_CURSOR", assertFailsWith<WebAccessDenied> {
            diffs(fixture).summary("owner", jobId, "run_2", "revision_2", "$base&cursor=${"a".repeat(64)}_1_${"b".repeat(32)}") }.code)
        assertEquals(0, fixture.reads)
        val paged = diffs(fixture)
        val first = paged.summary("owner", jobId, "run_2", "revision_2", "$base&limit=1")
        val cursor = first.getValue("page").jsonObject.getValue("nextCursor").jsonPrimitive.content
        assertEquals("b.c", items(paged.summary("owner", jobId, "run_2", "revision_2", "$base&limit=1&cursor=$cursor")).single()
            .getValue("headFile").jsonObject.getValue("displayName").jsonPrimitive.content)
        assertEquals("INVALID_CURSOR", assertFailsWith<WebAccessDenied> {
            paged.summary("other-session", jobId, "run_2", "revision_2", "$base&limit=1&cursor=$cursor") }.code)
    }

    @Test fun `multibyte and escaped lines keep every hunk page inside the response byte ceiling`() {
        for (unit in listOf("€", "\u0001")) {
            val before = (1..200).joinToString("") { "${unit.repeat(999)}a\n" }
            val after = (1..200).joinToString("") { "${unit.repeat(999)}b\n" }
            val fixture = fixture(listOf(side("src/wide.c", before)), listOf(side("src/wide.c", after)))
            val entry = items(diffs(fixture).summary("owner", jobId, "run_2", "revision_2", base)).single()
            var hunk: Int? = 0; var changed = 0
            while (hunk != null) {
                val page = diffs(fixture).file(jobId, "run_2", "revision_2", fileQuery(entry, hunk))
                assertEquals("text", page.getValue("representation").jsonPrimitive.content)
                // The envelope adds well under 1 KiB to the data object.
                assertTrue(page.toString().toByteArray().size < 1024 * 1024 - 1024, "page at hunk $hunk is ${page.toString().toByteArray().size} bytes")
                changed += page.getValue("hunks").jsonArray.sumOf { item -> item.jsonObject.getValue("lines").jsonArray.count {
                    it.jsonObject.getValue("kind").jsonPrimitive.content != "context" } }
                hunk = page.getValue("nextHunk").jsonPrimitive.intOrNull
            }
            assertEquals(400, changed, "every changed row stays reachable across pages")
        }
    }

    @Test fun `an added empty file is a text comparison without a patch that could not recreate it`() {
        val fixture = fixture(listOf(side("Makefile", "all:\n")), listOf(side("Makefile", "all:\n"), side("src/empty.c", "")))
        val entry = items(diffs(fixture).summary("owner", jobId, "run_2", "revision_2", base)).single()
        assertEquals("added", entry.getValue("status").jsonPrimitive.content)
        val result = diffs(fixture).file(jobId, "run_2", "revision_2", fileQuery(entry))
        assertEquals("text", result.getValue("representation").jsonPrimitive.content)
        assertEquals(0, result.getValue("totalHunks").jsonPrimitive.int)
        assertFalse(result.getValue("patchAvailable").jsonPrimitive.boolean)
        assertEquals("SOURCE_DIFF_NOT_TEXT", assertFailsWith<WebAccessDenied> {
            diffs(fixture).patch(jobId, "run_2", "revision_2", fileQuery(entry)) }.code)
    }

    @Test fun `a downloaded patch keeps long change groups whole so it applies with ordinary context`() {
        val before = (1..200).joinToString("") { "old $it\n" }
        val after = (1..200).joinToString("") { "new $it\n" }
        val fixture = fixture(listOf(side("src/a.c", before)), listOf(side("src/a.c", after)))
        val entry = items(diffs(fixture).summary("owner", jobId, "run_2", "revision_2", base)).single()
        // The display splits the 400-row group into 128-row hunks; the patch must not.
        assertEquals(4, diffs(fixture).file(jobId, "run_2", "revision_2", fileQuery(entry)).getValue("totalHunks").jsonPrimitive.int)
        val patch = String(diffs(fixture).patch(jobId, "run_2", "revision_2", fileQuery(entry)).bytes)
        assertEquals(1, Regex("(?m)^@@ ").findAll(patch).count())
        assertTrue(patch.contains("@@ -1,200 +1,200 @@\n"))
        assertEquals(after, applyPatch(before, patch))
    }

    @Test fun `body reads are bound to the compared metadata and a concurrent manifest change is refused`() {
        val fixture = fixture(listOf(side("src/a.c", "1\n")), listOf(side("src/a.c", "2\n")))
        val entry = items(diffs(fixture).summary("owner", jobId, "run_2", "revision_2", base)).single()
        val head = fixture.snapshots.getValue("run_2" to "revision_2")
        fixture.readerSnapshots = fixture.snapshots + (("run_2" to "revision_2") to
            WebRevisionSourceSnapshot(head.reference, "f".repeat(64), head.descriptorSha256, head.files))
        assertEquals("CURSOR_EXPIRED", assertFailsWith<WebAccessDenied> { diffs(fixture).file(jobId, "run_2", "revision_2", fileQuery(entry)) }.code)
        assertEquals("CURSOR_EXPIRED", assertFailsWith<WebAccessDenied> { diffs(fixture).patch(jobId, "run_2", "revision_2", fileQuery(entry)) }.code)
    }

    @Test fun `pinned hunk pages and patches refuse a comparison whose metadata changed`() {
        val fixture = fixture(listOf(side("src/a.c", "1\n")), listOf(side("src/a.c", "2\n")))
        val entry = items(diffs(fixture).summary("owner", jobId, "run_2", "revision_2", base)).single()
        val head = fixture.snapshots.getValue("run_2" to "revision_2"); val baseSnapshot = fixture.snapshots.getValue("run_1" to "revision_1")
        val pinned = "&metadataVersion=${head.metadataVersion}&baseMetadataVersion=${baseSnapshot.metadataVersion}"
        assertEquals(1, diffs(fixture).file(jobId, "run_2", "revision_2", fileQuery(entry) + pinned).getValue("totalHunks").jsonPrimitive.int)
        assertTrue(diffs(fixture).patch(jobId, "run_2", "revision_2", fileQuery(entry) + pinned).bytes.isNotEmpty())
        val stale = "&metadataVersion=${"0".repeat(64)}&baseMetadataVersion=${baseSnapshot.metadataVersion}"
        val reads = fixture.reads
        assertEquals("CURSOR_EXPIRED", assertFailsWith<WebAccessDenied> { diffs(fixture).file(jobId, "run_2", "revision_2", fileQuery(entry) + stale) }.code)
        assertEquals("CURSOR_EXPIRED", assertFailsWith<WebAccessDenied> { diffs(fixture).patch(jobId, "run_2", "revision_2", fileQuery(entry) + stale) }.code)
        assertEquals(reads, fixture.reads, "an expired pin is refused before any body read")
        assertEquals(422, assertFailsWith<WebAccessDenied> {
            diffs(fixture).file(jobId, "run_2", "revision_2", fileQuery(entry) + "&metadataVersion=${head.metadataVersion}") }.status)
    }

    @Test fun `myers edits are minimal on known pairs and bounded by the edit budget`() {
        fun edits(a: String, b: String, budget: Int = 100) = revisionLineEdits(a.map { it.code }.toIntArray(), b.map { it.code }.toIntArray(), budget) { false }
        val ops = assertNotNull(edits("ABCABBA", "CBABAC"))
        assertEquals(5, ops.count { it != WebDiffOp.EQUAL })
        assertEquals(7, ops.count { it != WebDiffOp.INSERT }); assertEquals(6, ops.count { it != WebDiffOp.DELETE })
        assertNull(edits("ABCABBA", "CBABAC", budget = 4))
        assertEquals(listOf(WebDiffOp.INSERT, WebDiffOp.INSERT), edits("", "AB"))
        assertNull(revisionLineEdits(intArrayOf(1, 2), intArrayOf(3, 4), 100) { true })
    }

    /** Minimal independent unified-diff applier used only to check patch fidelity. */
    private fun applyPatch(original: String, patch: String): String {
        val source = original.split('\n').dropLast(1).map { "$it\n" }.toMutableList()
        val output = StringBuilder(); var cursor = 0
        val lines = patch.split('\n').dropLast(1)
        var index = 2
        while (index < lines.size) {
            val header = Regex("@@ -(\\d+),(\\d+) \\+(\\d+),(\\d+) @@").matchEntire(lines[index++])!!
            val start = header.groupValues[1].toInt() - 1
            while (cursor < start) output.append(source[cursor++])
            while (index < lines.size && !lines[index].startsWith("@@")) {
                val line = lines[index++]
                val missingNewline = index < lines.size && lines[index] == "\\ No newline at end of file"
                when (line[0]) {
                    ' ' -> { output.append(source[cursor++]) }
                    '-' -> cursor++
                    '+' -> output.append(line.substring(1)).append(if (missingNewline) "" else "\n")
                }
                if (missingNewline) index++
            }
        }
        while (cursor < source.size) output.append(source[cursor++])
        return output.toString()
    }
}
