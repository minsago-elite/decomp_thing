package decompengine.web

import decompengine.project.ArchivalBundleLimits
import decompengine.project.ArchivalBundleVerifier
import decompengine.project.GeneratedCMakeReconstructionProfile
import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class WebArchiveEvidenceTest {
    @Test
    fun `snapshot extraction rejects depth before creating deep parents and removes partial payload`() {
        val root = Files.createTempDirectory("web-archive-depth-")
        try {
            val bytes = storedArchive(linkedMapOf("first.txt" to byteArrayOf(1), "deep/nested/file.txt" to byteArrayOf(2)))
            val failure = assertFailsWith<IllegalArgumentException> {
                ArchivalBundleVerifier.extractAndVerifySnapshot(
                    bytes, root.resolve("payload"), ArchivalBundleLimits(),
                    GeneratedCMakeReconstructionProfile.descriptor, maximumPathDepth = 2,
                )
            }
            assertTrue(failure.message.orEmpty().contains("depth bound"))
            assertTrue(Files.newDirectoryStream(root).use { !it.iterator().hasNext() })
        } finally {
            Files.delete(root)
        }
    }

    @Test
    fun `snapshot extraction enforces file count and aggregate expansion bounds with cleanup`() {
        val bytes = storedArchive(linkedMapOf("first.txt" to ByteArray(6), "second.txt" to ByteArray(6)))
        for (limits in listOf(
            ArchivalBundleLimits(maximumEntries = 1, maximumFileBytes = 8, maximumTotalBytes = 16),
            ArchivalBundleLimits(maximumEntries = 2, maximumFileBytes = 4, maximumTotalBytes = 8),
            ArchivalBundleLimits(maximumEntries = 2, maximumFileBytes = 8, maximumTotalBytes = 8),
        )) {
            val root = Files.createTempDirectory("web-archive-limit-")
            try {
                assertFailsWith<IllegalArgumentException> {
                    ArchivalBundleVerifier.extractAndVerifySnapshot(
                        bytes, root.resolve("payload"), limits,
                        GeneratedCMakeReconstructionProfile.descriptor, maximumPathDepth = 30,
                    )
                }
                assertTrue(Files.newDirectoryStream(root).use { !it.iterator().hasNext() })
            } finally {
                Files.delete(root)
            }
        }
    }

    @Test
    fun `verified archive reads retain the selected attempt namespace`() {
        val root = Files.createTempDirectory("web-archive-attempt-")
        try {
            val store = decompengine.jobs.JobStore(root)
            val bytes = decompengine.jobs.elfFixture()
            val job = store.createFromUpload("inert.elf", bytes)
            val prefix = "reports/runs/run_fixture"
            val tree = root.resolve(job.id).resolve("$prefix/source-tree")
            val inputHash = java.security.MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
            decompengine.project.SourceTreeGenerator.generate(decompengine.project.RecoveredProgramModel(
                inputSha256 = inputHash,
                functions = listOf(decompengine.project.RecoveredFunction("fn_1000", "core", 0x1000uL, "int core(void)")),
            ), tree)
            kotlin.test.assertEquals(0, decompengine.project.MakeProjectBuilder.build(tree).returnCode)
            val packed = decompengine.project.ArchivalPackager.create(tree, tree.parent.resolve("source-tree.zip"))
            val reads = mutableListOf<String>()
            val reader = { id: String, relative: String, limit: Long ->
                reads += relative
                store.readArtifact(id, relative, limit)
            }
            val sources = WebSourceEvidence(store, listOf(GeneratedCMakeReconstructionProfile.descriptor), reader)
            val archives = WebArchiveEvidence(store, sources, reader)
            kotlin.test.assertEquals(packed.archiveSha256, archives.read(job.id, reportPrefix = prefix).sha256)
            assertTrue(reads.isNotEmpty() && reads.all { it.startsWith("$prefix/") })
            assertFailsWith<Exception> { archives.read(job.id) }
            assertFailsWith<Exception> { archives.read(job.id, reportPrefix = "reports/runs/run_other") }
        } finally { root.toFile().deleteRecursively() }
    }

    @Test
    fun `losing an admitted source tree before the second receipt pass is a conflict`() {
        for (replaceWithLink in listOf(false, true)) {
            val root = Files.createTempDirectory("web-archive-receipt-race-")
            try {
                val store = decompengine.jobs.JobStore(root)
                val bytes = decompengine.jobs.elfFixture()
                val job = store.createFromUpload("inert.elf", bytes)
                val tree = root.resolve(job.id).resolve("reports/source-tree")
                val inputHash = java.security.MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
                decompengine.project.SourceTreeGenerator.generate(decompengine.project.RecoveredProgramModel(
                    inputSha256 = inputHash,
                    functions = listOf(decompengine.project.RecoveredFunction("fn_1000", "core", 0x1000uL, "int core(void)")),
                ), tree)
                kotlin.test.assertEquals(0, decompengine.project.MakeProjectBuilder.build(tree).returnCode)
                decompengine.project.ArchivalPackager.create(tree, tree.parent.resolve("source-tree.zip"))
                val profile = GeneratedCMakeReconstructionProfile.descriptor
                val artifactPath = decompengine.project.ReconstructionAdapters.resolve(profile).archiveBuild.contractPaths(profile).artifactPath
                var changed = false
                val reader = { id: String, relative: String, limit: Long ->
                    val snapshot = store.readArtifact(id, relative, limit)
                    // This executable read follows the first complete source receipt pass and precedes
                    // its revalidation. No sleeps or filesystem timing races are required.
                    if (!changed && relative == "reports/source-tree/$artifactPath") {
                        changed = true
                        if (replaceWithLink) {
                            val moved = tree.resolveSibling("source-tree.moved")
                            Files.move(tree, moved)
                            Files.createSymbolicLink(tree, moved)
                        } else assertTrue(tree.toFile().deleteRecursively())
                    }
                    snapshot
                }
                val sources = WebSourceEvidence(store, listOf(profile), reader)
                val archives = WebArchiveEvidence(store, sources, reader)
                assertFailsWith<decompengine.jobs.ArtifactChangedException> { archives.read(job.id) }
                assertTrue(changed, "the admitted tree was removed before receipt revalidation")
            } finally { root.toFile().deleteRecursively() }
        }
    }

    private fun storedArchive(entries: Map<String, ByteArray>): ByteArray {
        val bytes = ByteArrayOutputStream()
        ZipOutputStream(bytes).use { zip ->
            entries.forEach { (name, content) ->
                zip.putNextEntry(ZipEntry(name).apply {
                    method = ZipEntry.STORED
                    size = content.size.toLong()
                    compressedSize = size
                    crc = CRC32().apply { update(content) }.value
                })
                zip.write(content)
                zip.closeEntry()
            }
        }
        return bytes.toByteArray()
    }
}
