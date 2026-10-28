package decompengine.web

import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFileKey
import decompengine.project.*
import decompengine.repair.StableRegularFile
import kotlinx.serialization.json.*
import kotlin.test.*

/** Synthetic captured snapshots and byte arrays only. No store or listener is opened. */
class WebRevisionSourceSearchTest {
    private val jobId = "a".repeat(32)
    private val runId = "run_1"
    private val revisionId = "revision_1"
    private val owner = "session_1"
    private val text = setOf(ProjectFileRole.BUILD_INPUT, ProjectFileRole.VIEWABLE, ProjectFileRole.ARCHIVE_PAYLOAD)

    private class Entry(val path: String, val bytes: ByteArray, val roles: Set<ProjectFileRole>,
        val kind: ProjectContentKind = ProjectContentKind.UTF8_TEXT, val size: Long = bytes.size.toLong())

    private fun entry(path: String, body: String, roles: Set<ProjectFileRole> = text) = Entry(path, body.toByteArray(), roles)

    private fun snapshot(entries: List<Entry>, manifest: String = "b"): WebRevisionSourceSnapshot =
        WebRevisionSourceSnapshot(WebRevisionSourceReference(jobId, runId, revisionId, "d".repeat(64), "version_1"),
            manifest.repeat(64), "c".repeat(64), entries.map { entry ->
                WebRevisionSourceFile(GeneratedFileEvidence(entry.path, WebExplorationArtifact.sha256(entry.bytes), "fixture",
                    roles = entry.roles, contentKind = entry.kind), entry.size)
            })

    private class Harness(var snapshot: WebRevisionSourceSnapshot, var bodies: Map<String, ByteArray?>) {
        var reads = 0
        fun source(job: String, run: String, revision: String,
            scan: (WebRevisionSourceSnapshot, (WebRevisionSourceFile) -> ByteArray?) -> JsonObject): JsonObject {
            assertEquals(snapshot.reference.jobId, job); assertEquals(snapshot.reference.runId, run)
            assertEquals(snapshot.reference.revisionId, revision)
            return scan(snapshot) { file -> reads++; bodies[file.evidence.path] }
        }
    }

    private fun harness(entries: List<Entry>) = Harness(snapshot(entries), entries.associate { it.path to it.bytes })

    private fun search(engine: WebRevisionSourceSearch, query: String, session: String = owner): JsonObject =
        engine.search(session, jobId, runId, revisionId, query)

    private fun encode(value: String) = java.net.URLEncoder.encode(value, Charsets.UTF_8)
    private fun items(page: JsonObject) = page.getValue("items").jsonArray.map { it.jsonObject }
    private fun string(item: JsonObject, key: String) = item.getValue(key).jsonPrimitive.content
    private fun cursor(page: JsonObject) = page.getValue("page").jsonObject.getValue("nextCursor").jsonPrimitive.contentOrNull

    /** Collect every page, asserting each partial page reports an explicit reason and continuation. */
    private fun all(engine: WebRevisionSourceSearch, query: String, onPage: (JsonObject) -> Unit = {}): List<JsonObject> {
        val result = ArrayList<JsonObject>(); var next: String? = null; var pages = 0
        do {
            val page = search(engine, query + (next?.let { "&cursor=$it" } ?: "")); onPage(page); pages++
            result += items(page); next = cursor(page)
            assertEquals(next == null, page.getValue("status").jsonPrimitive.content == "complete")
            assertEquals(next == null, page.getValue("stopReason") is JsonNull)
            assertTrue(pages < 10_000)
        } while (next != null)
        return result
    }

    /** Independent fixture truth: every byte offset of the needle, non-overlapping, scanning the original bytes. */
    private fun truth(bytes: ByteArray, needle: String): List<Int> {
        val pattern = needle.toByteArray(); val offsets = ArrayList<Int>(); var index = 0
        while (index + pattern.size <= bytes.size) {
            if ((pattern.indices).all { bytes[index + it] == pattern[it] }) { offsets += index; index += pattern.size } else index++
        }
        return offsets
    }

    @Test fun `literal Unicode matches report exact revision byte line column and bounded context`() {
        val body = "α😀 needle\r\n<script>needle</script>\n東京needle needle\nno match\n" + "x".repeat(200) + "needle" + "y".repeat(200)
        val entries = listOf(entry("src/é space.c", body), entry("Makefile", "all: needle\n"))
        val engine = WebRevisionSourceSearch(harness(entries)::source)
        val page = search(engine, "q=needle")
        assertEquals("complete", page.getValue("status").jsonPrimitive.content)
        assertEquals("none", page.getValue("index").jsonPrimitive.content)
        val found = items(page).filter { string(it, "displayName") == "src/é space.c" }
        val bytes = body.toByteArray()
        assertEquals(truth(bytes, "needle").map { it.toString() }, found.map { string(it, "offsetBytes") })
        for (item in found) {
            val offset = string(item, "offsetBytes").toInt(); val lineStart = string(item, "lineOffsetBytes").toInt()
            assertEquals((1 + bytes.take(lineStart).count { it == 10.toByte() }).toString(), string(item, "line"))
            assertTrue(lineStart == 0 || bytes[lineStart - 1] == 10.toByte())
            val prefix = String(bytes, lineStart, offset - lineStart, Charsets.UTF_8)
            assertEquals((prefix.codePointCount(0, prefix.length) + 1).toString(), string(item, "column"))
            assertEquals("needle", string(item, "match"))
            assertTrue(string(item, "before").codePointCount(0, string(item, "before").length) <= 80)
            assertTrue(string(item, "after").codePointCount(0, string(item, "after").length) <= 80)
            assertFalse(string(item, "after").contains('\r'))
            assertEquals(revisionSourceFileId(snapshot(entries).reference, 1, "src/é space.c"), string(item, "fileId"))
        }
        assertEquals("α😀 ", string(found[0], "before")); assertEquals("4", string(found[0], "column"))
        assertEquals("<script>", string(found[1], "before")); assertEquals("</script>", string(found[1], "after"))
        val long = found.last()
        assertTrue(long.getValue("truncatedBefore").jsonPrimitive.boolean); assertTrue(long.getValue("truncatedAfter").jsonPrimitive.boolean)
        assertEquals("x".repeat(80), string(long, "before")); assertEquals("y".repeat(80), string(long, "after"))
        // Results follow canonical path order, so Makefile precedes src/.
        assertEquals("Makefile", string(items(page).first(), "displayName"))
    }

    @Test fun `search links retain canonical input identities when manifest entries precede the results`() {
        val harness = harness(listOf(entry("Makefile", "needle\n"), entry("src/a.c", "needle\n")))
        val legacy = harness.snapshot
        val report = WebRevisionSourceFile(GeneratedFileEvidence("A/report.json", "e".repeat(64), "fixture",
            roles = setOf(ProjectFileRole.VIEWABLE), contentKind = ProjectContentKind.UTF8_TEXT), null)
        harness.snapshot = WebRevisionSourceSnapshot(legacy.reference, legacy.manifestSha256, legacy.descriptorSha256, legacy.files + report)
        // Nullable manifest-only sizes must never acquire search admission or become a zero-byte charge.
        assertFailsWith<IllegalArgumentException> { sourceSearchReadReservation(report) }
        assertEquals(legacy.files[0].sizeBytes!! + 1, sourceSearchReadReservation(legacy.files[0]))
        val matches = all(WebRevisionSourceSearch(harness::source), "q=needle&limit=1")
        assertEquals(listOf("Makefile", "src/a.c"), matches.map { string(it, "displayName") })
        for ((index, item) in matches.withIndex()) {
            val id = string(item, "fileId")
            assertEquals(revisionSourceFileId(legacy.reference, index, legacy.files[index].evidence.path), id)
            assertSame(legacy.files[index], resolveRevisionSourceFile(harness.snapshot, id))
        }
    }

    @Test fun `case and symbol modes are explicit and symbol matches require identifier boundaries`() {
        val entries = listOf(entry("a.c", "int Count = count_total + COUNT;\ncount();\nÉcole école ÉCOLE\n"))
        val engine = WebRevisionSourceSearch(harness(entries)::source)
        assertEquals(listOf("count", "count"), items(search(engine, "q=count")).map { string(it, "match") })
        assertEquals(listOf("Count", "count", "COUNT", "count"), items(search(engine, "q=count&case=insensitive")).map { string(it, "match") })
        assertEquals(listOf("count"), items(search(engine, "q=count&match=symbol")).map { string(it, "match") })
        assertEquals(listOf("2"), items(search(engine, "q=count&match=symbol")).map { string(it, "line") })
        assertEquals(listOf("Count", "COUNT", "count"), items(search(engine, "q=count&match=symbol&case=insensitive")).map { string(it, "match") })
        assertEquals(listOf("count_total"), items(search(engine, "q=count_total&match=symbol")).map { string(it, "match") })
        assertEquals(listOf("École", "école", "ÉCOLE"), items(search(engine, "q=${encode("école")}&case=insensitive")).map { string(it, "match") })
        assertEquals(listOf("école"), items(search(engine, "q=${encode("école")}")).map { string(it, "match") })
        val echoed = search(engine, "q=count&match=symbol&case=insensitive").getValue("query").jsonObject
        assertEquals("symbol", echoed.getValue("match").jsonPrimitive.content)
        assertFalse(echoed.getValue("caseSensitive").jsonPrimitive.boolean)
    }

    @Test fun `scope reports skipped declarations unreadable text and unavailable bodies separately from no matches`() {
        val entries = listOf(
            entry("include/x.h", "needle\n"), entry("src/a.c", "needle\n"), entry("src/b.c", "nothing\n"),
            entry("src/hidden.c", "needle\n", setOf(ProjectFileRole.BUILD_INPUT)),
            Entry("src/blob.bin", "needle".toByteArray(), text, ProjectContentKind.BINARY),
            Entry("src/huge.c", "needle".toByteArray(), text, size = WebRevisionSourceContent.MAXIMUM_FILE_BYTES + 1),
            Entry("src/latin1.c", byteArrayOf('n'.code.toByte(), 0xe9.toByte()), text),
            entry("src/missing.c", "needle\n"),
        )
        val state = harness(entries).also { it.bodies = it.bodies + ("src/missing.c" to null) }
        val engine = WebRevisionSourceSearch(state::source)
        val captured = snapshot(entries)
        val directory = revisionSourceDirectoryId(captured, "src")
        val page = search(engine, "q=needle&directory=$directory")
        assertEquals(listOf("src/a.c"), items(page).map { string(it, "displayName") })
        val scope = page.getValue("scope").jsonObject
        assertEquals(7, scope.getValue("filesInScope").jsonPrimitive.int); assertEquals(4, scope.getValue("searchableFiles").jsonPrimitive.int)
        assertEquals(1, scope.getValue("notViewable").jsonPrimitive.int); assertEquals(1, scope.getValue("declaredBinary").jsonPrimitive.int)
        assertEquals(1, scope.getValue("tooLarge").jsonPrimitive.int)
        val progress = page.getValue("progress").jsonObject
        assertEquals(1, progress.getValue("unsearchableText").jsonPrimitive.int); assertEquals(1, progress.getValue("unavailableFiles").jsonPrimitive.int)
        assertEquals(3, progress.getValue("scannedFiles").jsonPrimitive.int); assertEquals(0, progress.getValue("remainingFiles").jsonPrimitive.int)
        // Undeclared, binary and oversized inputs are never read.
        assertEquals(4, state.reads)
        val filtered = search(engine, "q=needle&path=${encode("A.C")}&case=insensitive")
        assertEquals(listOf("src/a.c"), items(filtered).map { string(it, "displayName") })
        assertEquals(1, filtered.getValue("scope").jsonObject.getValue("filesInScope").jsonPrimitive.int)
        assertEquals(0, items(search(engine, "q=needle&path=A.C")).size)
        val none = search(engine, "q=absent")
        assertEquals("complete", none.getValue("status").jsonPrimitive.content); assertTrue(items(none).isEmpty())
        assertEquals("SOURCE_DIRECTORY_NOT_FOUND", assertFailsWith<WebAccessDenied> {
            search(engine, "q=needle&directory=dir_0_1_${"0".repeat(64)}")
        }.code)
    }

    @Test fun `continuations reproduce the single page result and stay bound to session query and metadata`() {
        val entries = (0 until 40).map { index -> entry("src/f%02d.c".format(index), "needle ".repeat(index % 4) + "\nneedle\n") }
        val state = harness(entries); val engine = WebRevisionSourceSearch(state::source)
        val complete = items(search(engine, "q=needle&limit=100")).map { string(it, "fileId") to string(it, "offsetBytes") }
        val paged = all(engine, "q=needle&limit=3") { page ->
            assertTrue(items(page).size <= 3)
            if (cursor(page) != null) assertEquals("result-limit", page.getValue("stopReason").jsonPrimitive.content)
        }.map { string(it, "fileId") to string(it, "offsetBytes") }
        assertEquals(complete, paged); assertEquals(entries.sumOf { truth(it.bytes, "needle").size }, paged.size)
        val next = cursor(search(engine, "q=needle&limit=3"))!!
        for (query in listOf("q=needles&limit=3", "q=needle&limit=4", "q=needle&limit=3&case=insensitive", "q=needle&limit=3&path=src",
            "q=needle&limit=3&match=symbol")) {
            assertEquals("INVALID_CURSOR", assertFailsWith<WebAccessDenied> { search(engine, "$query&cursor=$next") }.code)
        }
        assertEquals("INVALID_CURSOR", assertFailsWith<WebAccessDenied> { search(engine, "q=needle&limit=3&cursor=$next", "session_2") }.code)
        val forged = next.replaceAfterLast('_', "0".repeat(32))
        assertEquals("INVALID_CURSOR", assertFailsWith<WebAccessDenied> { search(engine, "q=needle&limit=3&cursor=$forged") }.code)
        // A new metadata observation expires every older continuation instead of reusing stale offsets.
        state.snapshot = snapshot(entries, manifest = "e")
        assertEquals("CURSOR_EXPIRED", assertFailsWith<WebAccessDenied> { search(engine, "q=needle&limit=3&cursor=$next") }.code)
    }

    @Test fun `scanned byte budget stops at file boundaries and continues without losing matches`() {
        val large = ("x".repeat(1023) + "\n").repeat(5 * 1024) + "needle\n"
        val entries = listOf(entry("a.c", large), entry("b.c", large), entry("c.c", "needle\n"))
        val state = harness(entries)
        val engine = WebRevisionSourceSearch(state::source, maximumScannedBytes = WebRevisionSourceContent.MAXIMUM_FILE_BYTES + 1)
        val first = search(engine, "q=needle")
        assertEquals("partial", first.getValue("status").jsonPrimitive.content)
        assertEquals("byte-limit", first.getValue("stopReason").jsonPrimitive.content)
        assertEquals(1, first.getValue("progress").jsonObject.getValue("scannedFiles").jsonPrimitive.int)
        assertEquals(2, first.getValue("progress").jsonObject.getValue("remainingFiles").jsonPrimitive.int)
        assertEquals(listOf("a.c", "b.c", "c.c"), all(engine, "q=needle") { page ->
            assertTrue(page.getValue("progress").jsonObject.getValue("scannedBytes").jsonPrimitive.long <= WebRevisionSourceContent.MAXIMUM_FILE_BYTES)
        }.map { string(it, "displayName") })
    }

    @Test fun `unavailable reads are charged to the scanned byte budget`() {
        val large = ("x".repeat(1023) + "\n").repeat(5 * 1024) + "needle\n"
        val entries = listOf(entry("a.c", large), entry("b.c", large), entry("c.c", large))
        val state = harness(entries).also { it.bodies = it.bodies + ("a.c" to null) + ("b.c" to null) }
        val engine = WebRevisionSourceSearch(state::source, maximumScannedBytes = WebRevisionSourceContent.MAXIMUM_FILE_BYTES + 1)
        val first = search(engine, "q=needle")
        // The failed 5 MiB read leaves no room for another 5 MiB read on this page.
        assertEquals("byte-limit", first.getValue("stopReason").jsonPrimitive.content)
        assertEquals(1, state.reads)
        assertEquals((entries[0].bytes.size + 1).toString(), first.getValue("progress").jsonObject.getValue("scannedBytes").jsonPrimitive.content)
        assertEquals(listOf("c.c"), all(engine, "q=needle").map { string(it, "displayName") })
    }

    @Test fun `page admission includes overflow probes at the maximum file size`() {
        val entries = (0 until 5).map { Entry("f$it.c", byteArrayOf(), text,
            size = WebRevisionSourceContent.MAXIMUM_FILE_BYTES) }
        val state = harness(entries).also { it.bodies = entries.associate { file -> file.path to null } }
        val engine = WebRevisionSourceSearch(state::source)
        val first = search(engine, "q=needle")
        val progress = first.getValue("progress").jsonObject
        // Four complete 8 MiB reservations plus their probes would exceed the unchanged 32 MiB ceiling.
        assertEquals(3, state.reads)
        assertEquals(3, progress.getValue("unavailableFiles").jsonPrimitive.int)
        assertEquals(3 * (WebRevisionSourceContent.MAXIMUM_FILE_BYTES + 1), progress.getValue("scannedBytes").jsonPrimitive.long)
        assertEquals("byte-limit", first.getValue("stopReason").jsonPrimitive.content)
        assertNotNull(cursor(first))
        val last = search(engine, "q=needle&cursor=${cursor(first)}")
        assertEquals(5, state.reads)
        assertEquals("complete", last.getValue("status").jsonPrimitive.content)
        assertEquals(5, last.getValue("coverageGaps").jsonObject.getValue("unavailableFiles").jsonPrimitive.int)
    }

    @Test fun `elapsed deadline stops with explicit progress and every continuation advances`() {
        val body = (1..3000).joinToString("") { if (it % 500 == 0) "needle $it\n" else "line $it\n" }
        val entries = listOf(entry("a.c", body), entry("b.c", body))
        var now = 0L
        val engine = WebRevisionSourceSearch(harness(entries)::source, nanoTime = { now.also { now += 1_000_000 } }, deadlineNanos = 3_000_000)
        val reasons = mutableSetOf<String>()
        val found = all(engine, "q=needle") { page -> page.getValue("stopReason").jsonPrimitive.contentOrNull?.let(reasons::add) }
        assertEquals(setOf("deadline"), reasons)
        assertEquals(entries.flatMap { e -> truth(e.bytes, "needle").map { e.path to it.toString() } },
            found.map { string(it, "displayName") to string(it, "offsetBytes") })
        assertEquals(12, found.size)
    }

    @Test fun `long lines are deadline checked within a line and resume without losing matches`() {
        // Fewer than 256 lines: matching these 192 KiB lines must still observe the deadline.
        val body = (1..20).joinToString("") { "a".repeat(192 * 1024) + "Needle $it\n" }
        val entries = listOf(entry("long.c", body))
        var now = 0L; var ticking = true
        val engine = WebRevisionSourceSearch(harness(entries)::source,
            nanoTime = { now.also { if (ticking) now += 1_000_000 } }, deadlineNanos = 3_000_000)
        val first = search(engine, "q=needle&case=insensitive")
        assertEquals("deadline", first.getValue("stopReason").jsonPrimitive.content)
        assertTrue(items(first).size < 20)
        val resume = cursor(first)!!.split('_')
        assertEquals("0", resume[1])
        val offset = resume[2].toInt()
        assertTrue(offset in 1 until 192 * 1024, "the first long line must be interrupted")
        ticking = false
        val continued = search(engine, "q=needle&case=insensitive&cursor=${cursor(first)}")
        assertEquals("complete", continued.getValue("status").jsonPrimitive.content)
        val found = items(first) + items(continued)
        assertEquals(truth(body.toByteArray(), "Needle").map { it.toString() }, found.map { string(it, "offsetBytes") })
    }

    @Test fun `repetitive maximum width queries stop inside the matcher and UTF-8 continuations advance`() {
        for (sensitive in listOf(true, false)) {
            val needle = "a".repeat(127) + "b"
            val body = "😀" + "a".repeat(128 * 1024) + needle + "😀" + "a".repeat(128 * 1024 - 264) + needle
            val bytes = body.toByteArray()
            assertEquals(256 * 1024, bytes.size)
            val entries = listOf(entry("repetitive.c", body))
            var now = 0L
            val engine = WebRevisionSourceSearch(harness(entries)::source,
                nanoTime = { now.also { now += 1_000_000 } }, deadlineNanos = 3_000_000)
            val query = "q=$needle&case=${if (sensitive) "sensitive" else "insensitive"}"
            val first = search(engine, query)
            assertEquals("deadline", first.getValue("stopReason").jsonPrimitive.content)
            assertTrue(items(first).isEmpty(), "stop before the first match, not only after a matching line")
            var previous = 0
            val found = all(engine, query) { page ->
                cursor(page)?.let {
                    val offset = it.split('_')[2].toInt()
                    assertTrue(offset > previous, "a continuation must advance within the same long line")
                    assertTrue((bytes[offset].toInt() and 0xc0) != 0x80, "UTF-8 boundary")
                    previous = offset
                }
            }
            assertEquals(truth(bytes, needle).map(Int::toString), found.map { string(it, "offsetBytes") })
        }
    }

    @Test fun `rejected symbol candidates observe the deadline and resume to the whole identifier`() {
        for (sensitive in listOf(true, false)) {
            val body = "😀" + "count_".repeat(2048) + " count 😀 count"
            val bytes = body.toByteArray()
            var now = 0L
            val engine = WebRevisionSourceSearch(harness(listOf(entry("symbols.c", body)))::source,
                nanoTime = { now.also { now += 1_000_000 } }, deadlineNanos = 3_000_000)
            val query = "q=count&match=symbol&case=${if (sensitive) "sensitive" else "insensitive"}"
            val first = search(engine, query)
            assertEquals("deadline", first.getValue("stopReason").jsonPrimitive.content)
            assertTrue(items(first).isEmpty())
            var previous = 0
            val found = all(engine, query) { page ->
                cursor(page)?.let {
                    val offset = it.split('_')[2].toInt()
                    assertTrue(offset > previous)
                    assertTrue((bytes[offset].toInt() and 0xc0) != 0x80)
                    previous = offset
                }
            }
            val expected = truth(bytes, " count").map { (it + 1).toString() }
            assertEquals(expected, found.map { string(it, "offsetBytes") })
        }
    }

    @Test fun `deadline checks between short successful matcher calls preserve nonoverlapping results`() {
        val body = "😀" + "aa ".repeat(80)
        var now = 0L
        val engine = WebRevisionSourceSearch(harness(listOf(entry("dense.c", body)))::source,
            nanoTime = { now.also { now += 1_000_000 } }, deadlineNanos = 3_000_000)
        val first = search(engine, "q=aa&limit=100")
        assertEquals("deadline", first.getValue("stopReason").jsonPrimitive.content)
        assertTrue(items(first).size in 1 until 80)
        val found = all(engine, "q=aa&limit=100")
        assertEquals(truth(body.toByteArray(), "aa").map(Int::toString), found.map { string(it, "offsetBytes") })
    }

    @Test fun `interruption is observed inside matching without clearing the thread flag`() {
        val body = "😀" + "a".repeat(4096) + "b"
        val state = harness(listOf(entry("long.c", body)))
        val engine = WebRevisionSourceSearch(state::source)
        val query = "q=${"a".repeat(127)}b&case=insensitive"
        val page = try {
            Thread.currentThread().interrupt()
            search(engine, query).also {
                assertEquals("deadline", it.getValue("stopReason").jsonPrimitive.content)
                assertNotNull(cursor(it))
                assertTrue(cursor(it)!!.split('_')[2].toInt() > 0)
                assertTrue(Thread.currentThread().isInterrupted)
            }
        } finally { Thread.interrupted() }
        val continued = search(engine, "$query&cursor=${cursor(page)}")
        assertEquals("complete", continued.getValue("status").jsonPrimitive.content)
        assertEquals(truth(body.toByteArray(), "a".repeat(127) + "b").map(Int::toString),
            items(continued).map { string(it, "offsetBytes") })
    }

    @Test fun `coverage gaps from earlier pages are carried by signed continuations`() {
        val entries = listOf(entry("a.c", "needle\n"), entry("b.c", "needle needle needle\n"), Entry("c.c", byteArrayOf(0xff.toByte()), text))
        val state = harness(entries).also { it.bodies = it.bodies + ("a.c" to null) }
        val engine = WebRevisionSourceSearch(state::source)
        val pages = mutableListOf<JsonObject>()
        val found = all(engine, "q=needle&limit=1") { pages += it }
        assertEquals(3, found.size); assertTrue(pages.size >= 3)
        assertEquals(1, pages.first().getValue("progress").jsonObject.getValue("unavailableFiles").jsonPrimitive.int)
        val last = pages.last()
        assertEquals(0, last.getValue("progress").jsonObject.getValue("unavailableFiles").jsonPrimitive.int)
        assertEquals(1, last.getValue("coverageGaps").jsonObject.getValue("unavailableFiles").jsonPrimitive.int)
        assertEquals(1, last.getValue("coverageGaps").jsonObject.getValue("unsearchableText").jsonPrimitive.int)
        val next = cursor(pages.first())!!
        val parts = next.split('_').toMutableList(); parts[4] = "0"
        assertEquals("INVALID_CURSOR", assertFailsWith<WebAccessDenied> { search(engine, "q=needle&limit=1&cursor=${parts.joinToString("_")}") }.code)
    }

    @Test fun `query grammar is closed bounded and canonical before any capture`() {
        val state = harness(listOf(entry("a.c", "x\n"))); val engine = WebRevisionSourceSearch(state::source)
        val invalid = listOf(null, "", "q=", "q=+", "q=${"a".repeat(129)}", "q=${encode("😀".repeat(129))}", "q=a%0Ab", "q=a%7Fb",
            "q=%zz", "q=%e9", "q=a%", "q=a&q=b", "q=a&path=", "q=a&path=${"p".repeat(257)}", "q=a&limit=0", "q=a&limit=101",
            "q=a&limit=01", "q=a&match=regex", "q=a&case=upper", "q=a.b&match=symbol", "q=1a&match=symbol", "q=a&other=1",
            "q=a&cursor", "q=a&directory=${"d".repeat(129)}", "q=a&q%3D=b", "q=a b")
        for (query in invalid) {
            assertEquals(422, assertFailsWith<WebAccessDenied>("$query") { engine.search(owner, jobId, runId, revisionId, query) }.status, "$query")
        }
        assertEquals("INVALID_CURSOR", assertFailsWith<WebAccessDenied> { search(engine, "q=a&cursor=nope") }.code)
        assertEquals("SOURCE_DIRECTORY_NOT_FOUND", assertFailsWith<WebAccessDenied> { search(engine, "q=a&directory=../x") }.code)
        assertEquals(0, state.reads)
        assertEquals("😀".repeat(128), search(engine, "q=${encode("😀".repeat(128))}").getValue("query").jsonObject.getValue("text").jsonPrimitive.content)
        assertEquals("a b+c", search(engine, "q=a+b%2Bc").getValue("query").jsonObject.getValue("text").jsonPrimitive.content)
    }

    @Test fun `evidence search verifies committed bodies shares admission and releases it after refusal`() {
        val profile = GeneratedCMakeReconstructionProfile.descriptor
        val payload = "int needle;\n".toByteArray()
        fun captured(bytes: ByteArray, inode: Long) = StableRegularFile(bytes, WebExplorationArtifact.sha256(bytes),
            LinuxFileIdentity(LinuxFileKey(1, inode), 0x8180, 1000, 1000, 1, 1, true, false, false))
        val input = captured("input".toByteArray(), 1)
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
        val evidence = WebSourceCatalogEvidence(listOf(profile), { input }, { _, path, _ ->
            when {
                path.endsWith("/source_tree_manifest.json") -> manifest
                path.endsWith("/build_contract.json") -> descriptor
                else -> error("Unexpected metadata target")
            }
        })
        for (mode in listOf("valid", "changed", "missing", "busy", "valid")) {
            val engine = WebRevisionSourceSearch({ _, _, _, scan ->
                evidence.search(reference, { job, run, path, maximum ->
                    assertEquals(jobId, job); assertEquals(runId, run)
                    assertEquals(if (path == "Makefile") 1L else payload.size.toLong(), maximum)
                    if (mode == "busy") assertEquals("SOURCE_SEARCH_BUSY", assertFailsWith<WebAccessDenied> {
                        evidence.search(reference, { _, _, _, _ -> error("nested") }) { _, _ -> JsonObject(emptyMap()) }
                    }.code)
                    when {
                        path == "Makefile" -> captured(byteArrayOf(), 4)
                        mode == "changed" -> captured("int other;\n".toByteArray(), 5)
                        mode == "missing" -> throw decompengine.jobs.JobStoreException("source input is unavailable")
                        else -> captured(payload, 5)
                    }
                }, scan)
            })
            if (mode == "changed") {
                assertEquals("SOURCE_REVISION_CHANGED", assertFailsWith<WebAccessDenied> { search(engine, "q=needle") }.code)
            } else {
                val page = search(engine, "q=needle")
                assertEquals(if (mode == "missing") 0 else 1, items(page).size)
                assertEquals(if (mode == "missing") 1 else 0, page.getValue("progress").jsonObject.getValue("unavailableFiles").jsonPrimitive.int)
            }
            evidence.readRevision(reference) // Admission is always released.
        }
    }
}
