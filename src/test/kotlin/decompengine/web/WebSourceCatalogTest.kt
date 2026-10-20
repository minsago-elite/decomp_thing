package decompengine.web

import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFileKey
import decompengine.project.*
import decompengine.repair.StableRegularFile
import java.security.MessageDigest
import kotlinx.serialization.json.*
import kotlin.test.*

/** In-memory manifests and callbacks only; no listener, provider, filesystem or worker is started. */
class WebSourceCatalogTest {
    private val jobId = "a".repeat(32)
    private val runId = "run_1"
    private val profile = GeneratedCMakeReconstructionProfile.descriptor
    private val moduleDeclaration = profile.layout.declarationForPath("src/modules/fixture.c")
    private val input = captured("input".toByteArray(), 1)

    private fun file(index: Int, path: String = "src/modules/m_${index.toString().padStart(5, '0')}.c"): GeneratedFileEvidence {
        return GeneratedFileEvidence(path, "b".repeat(64), "fixture", acceptedImplementation = false,
            roles = moduleDeclaration.roles, contentKind = moduleDeclaration.contentKind)
    }

    private fun manifest(files: List<GeneratedFileEvidence>, inputSha256: String = input.sha256): StableRegularFile = captured(
        SourceTreeManifest(profileId = profile.id, profileSha256 = profile.sha256, inputSha256 = inputSha256,
            files = files, unresolvedEntityIds = emptyList()).toJson().toByteArray(), 2)

    private fun captured(bytes: ByteArray, inode: Long): StableRegularFile = StableRegularFile(bytes,
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) },
        LinuxFileIdentity(LinuxFileKey(1, inode), 0x8180, 1000, 1000, 1, 1, true, false, false))

    private fun cursor(page: JsonObject): String? = page.getValue("page").jsonObject.getValue("nextCursor").jsonPrimitive.contentOrNull

    @Test fun `25000 manifest files are captured without reading source bodies and paged exactly once`() {
        val files = (0 until 25_000).map { file(it) }
        val document = manifest(files)
        assertTrue(document.bytes.size <= WebSourceCatalogEvidence.MAXIMUM_MANIFEST_BYTES)
        val reads = mutableListOf<String>()
        val evidence = WebSourceCatalogEvidence(listOf(profile), { id -> assertEquals(jobId, id); reads += "input"; input },
            { id, path, maximum ->
                assertEquals(jobId, id)
                assertEquals(WebSourceCatalogEvidence.MAXIMUM_MANIFEST_BYTES, maximum)
                reads += path
                document
            })
        val snapshot = evidence.read(jobId, runId)
        assertEquals(listOf("input", "reports/runs/run_1/source-tree/source_tree_manifest.json",
            "reports/runs/run_1/source-tree/source_tree_manifest.json", "input"), reads)
        val pages = WebSourceCatalogPages { job, run -> assertEquals(jobId, job); assertEquals(runId, run); snapshot }
        val seen = mutableListOf<String>()
        val ids = mutableSetOf<String>()
        var next: String? = null
        do {
            val page = pages.page("owner", jobId, runId, "limit=200" + (next?.let { "&cursor=$it" } ?: ""))
            assertEquals(25_000, page.getValue("totalFiles").jsonPrimitive.int)
            assertEquals(JsonNull, page.getValue("binding").jsonObject.getValue("revisionId"))
            assertEquals("manifest-metadata", page.getValue("authority").jsonPrimitive.content)
            val items = page.getValue("items").jsonArray
            assertTrue(items.size <= 200)
            for (item in items) {
                val value = item.jsonObject
                seen += value.getValue("displayName").jsonPrimitive.content
                assertTrue(ids.add(value.getValue("fileId").jsonPrimitive.content))
            }
            next = cursor(page)
        } while (next != null)
        assertEquals(files.map { it.path }, seen)
        assertEquals(4, reads.size) // Paging this capture performs no hidden file read.
    }

    @Test fun `cursor scope is checked before capture and changed manifests expire explicitly`() {
        var snapshot = WebSourceCatalogSnapshot("c".repeat(64), (0 until 60).map { file(it) })
        var captures = 0
        val pages = WebSourceCatalogPages { _, _ -> captures++; snapshot }
        val first = pages.page("owner", jobId, runId, null)
        assertEquals(first, pages.page("owner", jobId, runId, null))
        val next = checkNotNull(cursor(first))
        val before = captures
        for ((owner, job, run, query) in listOf(
            listOf("other", jobId, runId, "cursor=$next"),
            listOf("owner", "b".repeat(32), runId, "cursor=$next"),
            listOf("owner", jobId, "run_2", "cursor=$next"),
            listOf("owner", jobId, runId, "limit=25&cursor=$next"),
            listOf("owner", jobId, runId, "cursor=${next.dropLast(1)}Z"),
        )) assertEquals("INVALID_CURSOR", assertFailsWith<WebAccessDenied> { pages.page(owner, job, run, query) }.code)
        assertEquals(before, captures)
        snapshot = WebSourceCatalogSnapshot("d".repeat(64), snapshot.files)
        assertEquals("CURSOR_EXPIRED", assertFailsWith<WebAccessDenied> { pages.page("owner", jobId, runId, "cursor=$next") }.code)
        for (query in listOf("limit=201", "limit=1&limit=2", "path=src/main.c", "limit=%FF", "cursor=bad")) {
            assertFailsWith<WebAccessDenied> { pages.page("owner", jobId, runId, query) }
        }
    }

    @Test fun `byte limited pages continue from the actual emitted offset without losing long labels`() {
        val prefix = ("é".repeat(250) + "/").repeat(15)
        val files = (0 until 200).map { file(it, prefix + "m_${it.toString().padStart(5, '0')}.c") }
        val snapshot = WebSourceCatalogSnapshot("e".repeat(64), files)
        val pages = WebSourceCatalogPages { _, _ -> snapshot }
        val seen = mutableListOf<String>()
        var next: String? = null
        do {
            val page = pages.page("owner", jobId, runId, "limit=200" + (next?.let { "&cursor=$it" } ?: ""))
            assertTrue(page.toString().toByteArray().size < 1_048_000)
            val items = page.getValue("items").jsonArray
            assertTrue(items.size in 1..199)
            seen += items.map { it.jsonObject.getValue("displayName").jsonPrimitive.content }
            next = cursor(page)
        } while (next != null)
        assertEquals(files.map { it.path }, seen)
    }

    @Test fun `changed capture identity input or manifest withholds the entire catalog`() {
        val document = manifest(listOf(file(0)))
        var manifestReads = 0
        val changed = WebSourceCatalogEvidence(listOf(profile), { input }, { _, _, _ ->
            manifestReads++
            if (manifestReads == 1) document else captured(document.bytes, 3)
        })
        assertEquals("SOURCE_CATALOG_CHANGED", assertFailsWith<WebAccessDenied> { changed.read(jobId, runId) }.code)
        var inputReads = 0
        val changedInput = WebSourceCatalogEvidence(listOf(profile), {
            inputReads++; if (inputReads == 1) input else captured("replacement".toByteArray(), 4)
        }, { _, _, _ -> document })
        assertEquals("SOURCE_CATALOG_CHANGED", assertFailsWith<WebAccessDenied> { changedInput.read(jobId, runId) }.code)
        val foreign = manifest(listOf(file(0)), "f".repeat(64))
        assertFailsWith<IllegalArgumentException> {
            WebSourceCatalogEvidence(listOf(profile), { input }, { _, _, _ -> foreign }).read(jobId, runId)
        }
    }

    @Test fun `catalog capture owns its metadata list and rejects duplicate or excess records`() {
        val files = mutableListOf(file(1), file(0))
        val snapshot = WebSourceCatalogSnapshot("a".repeat(64), files)
        files.clear()
        assertEquals(listOf(file(0).path, file(1).path), snapshot.files.map { it.path })
        assertFailsWith<IllegalArgumentException> { WebSourceCatalogSnapshot("a".repeat(64), listOf(file(0), file(0))) }
        assertFailsWith<IllegalArgumentException> { WebSourceCatalogSnapshot("a".repeat(64), (0..25_000).map { file(it) }) }
    }

    @Test fun `metadata ceiling host profile and normalized declarations cannot be bypassed by captured bytes`() {
        val text = manifest(listOf(file(0))).bytes.toString(Charsets.UTF_8)
        val invalid = listOf(
            text.replace(profile.sha256, "f".repeat(64)).toByteArray(),
            text.replace(file(0).path, "../input.elf").toByteArray(),
            text.replace("\"acceptedImplementation\": false", "\"acceptedImplementation\": null").toByteArray(),
            ByteArray(WebSourceCatalogEvidence.MAXIMUM_MANIFEST_BYTES.toInt() + 1),
        )
        for (bytes in invalid) {
            val document = captured(bytes, 2)
            assertFailsWith<IllegalArgumentException> {
                WebSourceCatalogEvidence(listOf(profile), { input }, { _, _, _ -> document }).read(jobId, runId)
            }
        }
    }

    @Test fun `one catalog capture is admitted and failure always releases admission`() {
        val snapshot = WebSourceCatalogSnapshot("a".repeat(64), listOf(file(0)))
        lateinit var pages: WebSourceCatalogPages
        var fail = true
        pages = WebSourceCatalogPages { _, _ ->
            assertEquals("SOURCE_CATALOG_BUSY", assertFailsWith<WebAccessDenied> {
                pages.page("other", jobId, runId, null)
            }.code)
            if (fail) throw IllegalStateException("inert capture failure")
            snapshot
        }
        assertFailsWith<IllegalStateException> { pages.page("owner", jobId, runId, null) }
        fail = false
        assertEquals(1, pages.page("owner", jobId, runId, null).getValue("items").jsonArray.size)
        assertEquals(1, pages.page("owner", jobId, runId, null).getValue("items").jsonArray.size)
    }
}
