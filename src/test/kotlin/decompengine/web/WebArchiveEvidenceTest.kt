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
