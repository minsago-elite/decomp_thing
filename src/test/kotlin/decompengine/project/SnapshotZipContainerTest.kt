package decompengine.project

import java.io.IOException
import java.nio.file.Files
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import org.apache.commons.compress.archivers.zip.Zip64Mode
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream
import org.apache.commons.compress.utils.SeekableInMemoryByteChannel
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SnapshotZipContainerTest {
    private val note = "ordinary retained note".toByteArray()
    private val name = "notes/café.txt"

    private fun archive(mode: Zip64Mode, names: List<String> = listOf(name)): ByteArray {
        val channel = SeekableInMemoryByteChannel()
        ZipArchiveOutputStream(channel).use { output ->
            output.setUseZip64(mode)
            // The seekable writer fills in unknown STORED sizes after the content is written.
            for (path in names) {
                output.putArchiveEntry(ZipArchiveEntry(path).apply { method = ZipEntry.STORED })
                output.write(note)
                output.closeArchiveEntry()
            }
        }
        return channel.array().copyOf(channel.size().toInt())
    }

    @Test
    fun `ordinary seekable STORED writers agree with streamed names sizes and CRCs`() {
        for (mode in listOf(Zip64Mode.Never, Zip64Mode.AsNeeded, Zip64Mode.Always, Zip64Mode.AlwaysWithCompatibility)) {
            val bytes = archive(mode)
            val directory = SnapshotZipContainer(bytes).validate(ArchivalBundleLimits()).single()
            assertEquals(name, directory.name)
            ZipInputStream(bytes.inputStream()).use { input ->
                val entry = input.nextEntry
                assertTrue(directory.matches(entry))
                assertContentEquals(note, input.readAllBytes())
                assertEquals(null, input.nextEntry)
            }
        }
    }

    @Test
    fun `directory preflight enforces the configured entry budget`() {
        val bytes = archive(Zip64Mode.Always, listOf("first.txt", "second.txt"))
        val failure = assertFailsWith<IllegalArgumentException> {
            SnapshotZipContainer(bytes).validate(ArchivalBundleLimits(maximumEntries = 1))
        }
        assertEquals("snapshot ZIP directory exceeds the entry limit", failure.message)
        assertEquals(2, SnapshotZipContainer(bytes).validate(ArchivalBundleLimits(maximumEntries = 2)).size)
    }

    @Test
    fun `incomplete archive leaves existing and absent targets untouched`() {
        val root = Files.createTempDirectory("snapshot-incomplete-")
        try {
            val existing = Files.createDirectory(root.resolve("existing"))
            val absent = root.resolve("absent")
            val bytes = archive(Zip64Mode.Never)
            for (length in listOf(bytes.size / 2, bytes.size - 22, bytes.size - 1)) {
                for (target in listOf(existing, absent)) {
                    assertFailsWith<IllegalArgumentException> {
                        ArchivalBundleVerifier.extractAndVerifySnapshot(bytes.copyOf(length), target, ArchivalBundleLimits(),
                            GeneratedCMakeReconstructionProfile.descriptor, 30)
                    }
                    assertFalse(Files.exists(absent))
                    assertTrue(Files.list(existing).use { it.findAny().isEmpty })
                    assertEquals(listOf(existing), Files.list(root).use { it.toList() })
                }
            }

            val file = Files.createFile(root.resolve("file"))
            assertFailsWith<IOException> {
                ArchivalBundleVerifier.extractAndVerifySnapshot(bytes, file.resolve("payload"), ArchivalBundleLimits(),
                    GeneratedCMakeReconstructionProfile.descriptor, 30)
            }
        } finally {
            root.toFile().deleteRecursively()
        }
    }

    @Test
    fun `metadata extents must fit before narrowing to array indexes`() {
        assertEquals(Int.MAX_VALUE, SnapshotZipContainer.extent(Int.MAX_VALUE - 1, 1, Int.MAX_VALUE))
        for (length in listOf(-1L, 2L, 0xffff_ffffL, Long.MAX_VALUE)) {
            assertFailsWith<IllegalArgumentException> {
                SnapshotZipContainer.extent(Int.MAX_VALUE - 1, length, Int.MAX_VALUE)
            }
        }
        assertFailsWith<IllegalArgumentException> { SnapshotZipContainer.extent(-1, 0, 0) }
        assertFailsWith<IllegalArgumentException> { SnapshotZipContainer.extent(10, 0, 9) }
    }
}
