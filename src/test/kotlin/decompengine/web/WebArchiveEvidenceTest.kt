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
import kotlin.test.assertEquals
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
            // Other namespaces have no archive: each is refused as a missing pinned read, never served from this attempt.
            // A missing final file is refused by the pinned read itself; a missing namespace directory by the store.
            val missingFile = assertFailsWith<decompengine.jobs.JobStoreException> { archives.read(job.id) }
            assertEquals("artifact is unavailable", missingFile.message)
            val missingNamespace = assertFailsWith<decompengine.jobs.JobStoreException> {
                archives.read(job.id, reportPrefix = "reports/runs/run_other")
            }
            assertEquals("artifact is unavailable or its path changed", missingNamespace.message)
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

    @Test
    fun `admitted archive rereads report unavailable changed and over-budget objects as conflicts`() {
        for (target in listOf("archive", "executable", "input", "manifest")) {
            for (mutation in listOf("delete", "link", "content", "identity", "grow")) {
                val root = Files.createTempDirectory("web-archive-final-race-")
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
                    val selected = when (target) {
                        "archive" -> tree.parent.resolve("source-tree.zip")
                        "executable" -> tree.resolve(artifactPath)
                        "input" -> root.resolve(job.id).resolve("input.elf")
                        else -> tree.resolve("source_tree_manifest.json")
                    }
                    var executableReads = 0
                    var manifestReads = 0
                    var changed = false
                    val reader = { id: String, relative: String, limit: Long ->
                        val snapshot = store.readArtifact(id, relative, limit)
                        if (relative == "reports/source-tree/$artifactPath") executableReads++
                        if (relative == "reports/source-tree/source_tree_manifest.json") manifestReads++
                        // The second executable read is after receipt revalidation; the final
                        // manifest's first/last reads are numbers 3/4. Mutate just before the
                        // chosen object's last reread, never relying on sleeps or a racing thread.
                        val trigger = when (target) {
                            "archive", "input" -> relative == "reports/source-tree/$artifactPath" && executableReads == 2
                            "executable" -> relative == "reports/source-tree/source_tree_manifest.json" && manifestReads == 4
                            else -> relative == "reports/source-tree/source_tree_manifest.json" && manifestReads == 3
                        }
                        if (!changed && trigger) {
                            changed = true
                            when (mutation) {
                                "delete" -> Files.delete(selected)
                                "link" -> {
                                    val private = root.resolve("private-canary")
                                    Files.writeString(private, "PRIVATE_REVALIDATION_CANARY")
                                    Files.delete(selected)
                                    Files.createSymbolicLink(selected, private)
                                }
                                "content" -> Files.writeString(selected, "PRIVATE_REVALIDATION_CANARY")
                                "identity" -> {
                                    val replacement = selected.resolveSibling("replacement")
                                    Files.copy(selected, replacement)
                                    Files.move(replacement, selected, java.nio.file.StandardCopyOption.REPLACE_EXISTING)
                                }
                                "grow" -> java.io.RandomAccessFile(selected.toFile(), "rw").use { it.setLength(64L * 1024 * 1024 + 1) }
                            }
                        }
                        snapshot
                    }
                    val sources = WebSourceEvidence(store, listOf(profile), reader)
                    val archives = WebArchiveEvidence(store, sources, reader)
                    val failure = assertFailsWith<decompengine.jobs.ArtifactChangedException>("$target/$mutation") { archives.read(job.id) }
                    assertTrue(changed, "$target/$mutation reached the admitted reread")
                    assertTrue(!failure.message.orEmpty().contains(root.toString()) &&
                        !failure.message.orEmpty().contains("PRIVATE_REVALIDATION_CANARY"))
                } finally { root.toFile().deleteRecursively() }
            }
        }
    }

    @Test
    fun `initially absent or invalid archives retain their original refusals`() {
        val root = Files.createTempDirectory("web-archive-initial-")
        try {
            val store = decompengine.jobs.JobStore(root)
            val job = store.createFromUpload("inert.elf", decompengine.jobs.elfFixture())
            val sources = WebSourceEvidence(store, listOf(GeneratedCMakeReconstructionProfile.descriptor))
            val archives = WebArchiveEvidence(store, sources)
            val missing = assertFailsWith<decompengine.jobs.JobStoreException> { archives.read(job.id) }
            assertTrue(missing !is decompengine.jobs.ArtifactChangedException)
            Files.writeString(store.reportsDirectory(job.id).resolve("source-tree.zip"), "not a valid archive")
            assertFailsWith<IllegalArgumentException> { archives.read(job.id, "0".repeat(64)) }
        } finally { root.toFile().deleteRecursively() }
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
