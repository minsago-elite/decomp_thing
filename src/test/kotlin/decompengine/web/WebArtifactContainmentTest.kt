package decompengine.web

import decompengine.jobs.ArtifactChangedException
import decompengine.jobs.JobStore
import decompengine.jobs.JobStoreException
import decompengine.jobs.elfFixture
import decompengine.project.ArchiveTransportLayout
import decompengine.repair.RepairBudgetExceededException
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.time.Duration
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Public artifact identities are normalized once and every read goes through the shared
 * descriptor-pinned containment boundary. Benign INSIDE/OUTSIDE marker files show that no
 * spelling, link or concurrent change can return bytes from outside the admitted snapshot.
 */
class WebArtifactContainmentTest {
    private val client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build()

    private fun directory(name: String): Path =
        Files.createTempDirectory(Files.createDirectories(Path.of("build/test-tmp/web-containment").toAbsolutePath()), "$name-")

    private fun refused(block: () -> Unit) {
        val failure = assertFailsWith<WebAccessDenied> { block() }
        assertEquals(400, failure.status)
        assertEquals("INVALID_REQUEST", failure.code)
        assertFalse(failure.message.orEmpty().contains("..") || failure.message.orEmpty().contains("%"))
    }

    @Test fun `one canonical spelling is accepted for each contained name`() {
        assertEquals("reports/a.txt", WebPublicIdentity.relativePath(listOf("reports", "a.txt")))
        assertEquals("reports/a+b c.txt", WebPublicIdentity.relativePath(listOf("reports", "a+b%20c.txt")))
        assertEquals("reports/\u00e9t\u00e9.txt", WebPublicIdentity.relativePath(listOf("reports", "%C3%A9t%C3%A9.txt")))
        assertEquals("reports/\uD83D\uDE00.txt", WebPublicIdentity.relativePath(listOf("reports", "%F0%9F%98%80.txt")))
        assertEquals("0123456789abcdef0123456789abcdef", WebPublicIdentity.segment("0123456789abcdef0123456789abcdef"))
        assertEquals("reports/x.txt", WebPublicIdentity.canonicalRelativePath("reports/x.txt"))
        val refusedSegments = listOf(
            "..", ".", "%2e%2e", "%2E", "a%2Fb", "a%5Cb", "%00", "a%0Ab", "C%3A", "%5C%5Cserver", "a%",
            "a%zz", "%252e%252e", "%C0%AE", "%E2%80%AEtxt.exe", "a%E2%80%8Bb", "e%CC%81", "CON", "con.txt", "Nul",
            "COM1.log", "lpt9", "a.", "a%20", "%20a", "", "\u00e9", "a b",
            "a%F3%A0%80%81.txt", "a%F3%A0%81%A1.txt", "a%F3%A0%81%BF.txt",
        )
        for (segment in refusedSegments) refused { WebPublicIdentity.relativePath(listOf("reports", segment)) }
        for (codePoint in listOf(0xE0001, 0xE0061, 0xE007F)) {
            val name = "a${String(Character.toChars(codePoint))}.txt"
            refused { WebPublicIdentity.canonicalRelativePath("reports/$name") }
        }
        refused { WebPublicIdentity.relativePath(List(33) { "a" }) }
        refused { WebPublicIdentity.relativePath(listOf("a".repeat(256))) }
        refused { WebPublicIdentity.relativePath(emptyList()) }
        for (path in listOf("/etc/passwd", "reports//x", "reports/../x", "C:\\x", "reports/x\\y", "reports/./x"))
            refused { WebPublicIdentity.canonicalRelativePath(path) }
    }

    @Test fun `legacy downloads never follow links, encodings or special files outside the admitted snapshot`() {
        val root = directory("legacy")
        val outside = directory("outside")
        try {
            Files.writeString(outside.resolve("secret.txt"), "OUTSIDE_MARKER")
            val store = JobStore(root)
            val job = store.createFromUpload("fixture.elf", elfFixture())
            val reports = Files.createDirectories(root.resolve(job.id).resolve("reports"))
            Files.writeString(reports.resolve("inside.txt"), "INSIDE_MARKER")
            Files.writeString(reports.resolve("a+b.txt"), "PLUS_MARKER")
            Files.createSymbolicLink(reports.resolve("link.txt"), outside.resolve("secret.txt"))
            Files.createSymbolicLink(reports.resolve("linked-dir"), outside)
            assertEquals(0, ProcessBuilder("mkfifo", reports.resolve("fifo").toString()).start().waitFor())
            val server = UploadServer("127.0.0.1", 0, root, JobAnalyzer { _, _ -> error("unexpected") },
                JobReconstructor { _, _ -> error("unexpected") })
            server.start()
            try {
                val headers = legacySessionHeaders(server)
                fun get(tail: String): HttpResponse<String> = client.send(HttpRequest.newBuilder(
                    URI.create("http://127.0.0.1:${server.serverPort}/jobs/${job.id}/artifacts/$tail")).timeout(Duration.ofSeconds(10))
                    .apply { headers.forEach { (k, v) -> header(k, v) } }.GET().build(), HttpResponse.BodyHandlers.ofString())
                assertEquals("INSIDE_MARKER", get("reports/inside.txt").body())
                assertEquals("PLUS_MARKER", get("reports/a+b.txt").body(), "'+' is a literal plus in a path")
                assertEquals("PLUS_MARKER", get("reports/a%2Bb.txt").body())
                for ((codePoint, encoded) in listOf(0xE0001 to "%F3%A0%80%81", 0xE0061 to "%F3%A0%81%A1", 0xE007F to "%F3%A0%81%BF")) {
                    Files.writeString(reports.resolve("a${String(Character.toChars(codePoint))}.txt"), "INVISIBLE_NAME_MARKER")
                    val response = get("reports/a$encoded.txt")
                    assertEquals(400, response.statusCode(), encoded)
                    assertTrue(response.body().contains("INVALID_REQUEST"))
                    assertFalse(response.body().contains("INVISIBLE_NAME_MARKER"))
                }
                val attempts = listOf("reports/link.txt", "reports/linked-dir/secret.txt", "reports/fifo",
                    "reports/%2e%2e/%2e%2e/${outside.fileName}/secret.txt", "reports/..%2F..%2Fjob.json", "reports/%252e%252e/job.json",
                    "reports%2F..%2F..%2Fjob.json", "reports/inside.txt%00.png", "reports/INSIDE.TXT%E2%80%AE",
                    "reports//inside.txt", "reports/missing.txt", "reports/CON")
                for (attempt in attempts) {
                    val response = get(attempt)
                    assertTrue(response.statusCode() in setOf(400, 404), "$attempt -> ${response.statusCode()}")
                    assertFalse(response.body().contains("OUTSIDE_MARKER") || response.body().contains(outside.toString()), attempt)
                    assertFalse(response.body().contains(root.toString()), attempt)
                }
                assertEquals(0, openDescriptorsUnder(root), "denied reads release every descriptor")
                assertEquals(0, openDescriptorsUnder(outside))
            } finally { server.stop() }
        } finally { root.toFile().deleteRecursively(); outside.toFile().deleteRecursively() }
    }

    @Test fun `receipts stream sizes and digests and changed or growing files are explicit conflicts`() {
        val root = directory("receipts")
        try {
            val store = JobStore(root)
            val job = store.createFromUpload("fixture.elf", elfFixture())
            val tree = Files.createDirectories(root.resolve(job.id).resolve("reports/source-tree/src"))
            Files.writeString(tree.resolve("a.c"), "int a;\n")
            Files.writeString(tree.parent.resolve("README"), "readme\n")
            val receipt = store.artifactReceipt(job.id, "reports/source-tree/src/a.c", 1024)
            assertEquals(7, receipt.sizeBytes)
            assertEquals(sha256("int a;\n".toByteArray()), receipt.sha256)
            assertEquals("observed-digest", receipt.verification)
            assertFailsWith<RepairBudgetExceededException> { store.artifactReceipt(job.id, "reports/source-tree/src/a.c", 3) }
            assertFailsWith<JobStoreException> { store.artifactReceipt(job.id, "reports/source-tree/src/missing.c", 1024) }

            // A writer appending while the receipt is streamed: never a receipt over mixed bytes.
            var appended = false
            assertFailsWith<ArtifactChangedException> {
                store.artifactReceipt(job.id, "reports/source-tree/src/a.c", 1024) {
                    // Append only once the pinned descriptor is open, i.e. during the streamed read.
                    if (!appended && openDescriptorsUnder(tree) > 0) {
                        appended = true
                        Files.writeString(tree.resolve("a.c"), "int b;\n", java.nio.file.StandardOpenOption.APPEND)
                    }
                }
            }
            assertTrue(appended)
            var calls = 0
            // Replacing the file by rename while it is read is the same explicit conflict.
            calls = 0
            assertFailsWith<ArtifactChangedException> {
                containedReadWithHook(root, job.id) {
                    if (++calls == 2) {
                        Files.writeString(tree.resolve("a.c.new"), "replaced\n")
                        Files.move(tree.resolve("a.c.new"), tree.resolve("a.c"), java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                            java.nio.file.StandardCopyOption.REPLACE_EXISTING)
                    }
                }
            }

            val layout = ArchiveTransportLayout(setOf("build"), emptySet())
            val receipts = store.sourceArchiveReceipts(job.id, layout)
            assertEquals(setOf("README", "src/a.c"), receipts.files.keys)
            assertEquals(receipts.files.values.sumOf { it.sizeBytes }, receipts.totalBytes)
            assertEquals(receipts, store.sourceArchiveReceipts(job.id, layout), "an unchanged snapshot reproduces its receipts")
            // Publication during inventory receipts: a new file appears after the first receipt.
            calls = 0
            assertFailsWith<ArtifactChangedException> {
                store.sourceArchiveReceipts(job.id, layout) { if (++calls == 1) Files.writeString(tree.resolve("b.c"), "int b;\n") }
            }
            // Deletion during receipts: the second file disappears before it is read.
            Files.delete(tree.resolve("b.c"))
            calls = 0
            assertFailsWith<ArtifactChangedException> {
                store.sourceArchiveReceipts(job.id, layout) { if (++calls == 1) Files.delete(tree.resolve("a.c")) }
            }
            Files.writeString(tree.resolve("a.c"), "int a;\n")
            // Replacement of the whole admitted tree after every receipt, before the final inventory pass:
            // the last callback runs after the last file was revalidated.
            var total = 0
            store.sourceArchiveReceipts(job.id, layout) { total++ }
            val sourceTree = tree.parent
            val moved = sourceTree.resolveSibling("source-tree.moved")
            calls = 0
            assertFailsWith<ArtifactChangedException> {
                store.sourceArchiveReceipts(job.id, layout) {
                    if (++calls == total) {
                        Files.move(sourceTree, moved)
                        Files.createSymbolicLink(sourceTree, moved)
                    }
                }
            }
            Files.delete(sourceTree)
            Files.move(moved, sourceTree)
            calls = 0
            assertFailsWith<ArtifactChangedException> {
                store.sourceArchiveReceipts(job.id, layout) { if (++calls == total) sourceTree.toFile().deleteRecursively() }
            }
            Files.createDirectories(tree)
            Files.writeString(tree.resolve("a.c"), "int a;\n")
            Files.writeString(tree.parent.resolve("README"), "readme\n")
            assertFailsWith<RepairBudgetExceededException> {
                store.sourceArchiveReceipts(job.id, layout, maximumFileBytes = 4, maximumTotalBytes = 4)
            }
            assertEquals(0, openDescriptorsUnder(root), "every refused receipt released its descriptors")
        } finally { root.toFile().deleteRecursively() }
    }

    @Test fun `receipt completion detects in-place writes to an already completed file`() {
        val root = directory("receipt-content-race")
        try {
            val store = JobStore(root)
            val job = store.createFromUpload("fixture.elf", elfFixture())
            val tree = Files.createDirectories(root.resolve(job.id).resolve("reports/source-tree"))
            val first = tree.resolve("a.txt")
            val second = tree.resolve("b.txt")
            Files.writeString(first, "A0")
            Files.writeString(second, "B0")
            val layout = ArchiveTransportLayout(emptySet(), emptySet())
            val before = store.sourceArchiveInventory(job.id, layout)
            // Count the primitive's callbacks rather than depending on its implementation's open/read count.
            var firstCallbacks = 0
            store.artifactReceipt(job.id, "reports/source-tree/a.txt", 1024) { firstCallbacks++ }
            var calls = 0
            var mutated = false
            assertFailsWith<ArtifactChangedException> {
                store.sourceArchiveReceipts(job.id, layout) {
                    // One outer callback, all callbacks for a.txt, then b.txt's outer callback.
                    if (++calls == firstCallbacks + 2) {
                        Files.writeString(first, "A1")
                        Files.writeString(second, "B1")
                        mutated = true
                    }
                }
            }
            assertTrue(mutated)
            assertEquals(before, store.sourceArchiveInventory(job.id, layout), "the inodes did not change")
            val current = store.sourceArchiveReceipts(job.id, layout)
            assertEquals(sha256("A1".toByteArray()), current.files.getValue("a.txt").sha256)
            assertEquals(sha256("B1".toByteArray()), current.files.getValue("b.txt").sha256)
            assertEquals(4, current.totalBytes)
            assertEquals(0, openDescriptorsUnder(root), "conflicted receipts release every descriptor")
        } finally { root.toFile().deleteRecursively() }
    }

    /** Reads through the same contained primitive as every adapter, with a mid-read hook. */
    private fun containedReadWithHook(root: Path, jobId: String, during: () -> Unit) {
        try {
            decompengine.repair.readStableRegularFile(root, "$jobId/reports/source-tree/src/a.c", 1024,
                afterAuthorization = during, afterRead = during)
        } catch (failure: decompengine.repair.StableFileChangedException) {
            throw ArtifactChangedException(failure.message ?: "changed")
        }
    }

    private fun openDescriptorsUnder(root: Path): Int {
        val prefix = root.toAbsolutePath().normalize().toString()
        return Files.list(Path.of("/proc/self/fd")).use { entries ->
            entries.toList().mapNotNull { runCatching { Files.readSymbolicLink(it).toString() }.getOrNull() }
                .count { it.startsWith(prefix) && !it.endsWith("-owner.lock") }
        }
    }

    private fun sha256(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
}
