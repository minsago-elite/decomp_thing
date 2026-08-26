package decompengine.project

import java.nio.file.Files
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class ArchivalBundleTest {
    @Test
    fun `identical source trees produce byte-identical verified archives`() {
        val temp = createTempDirectory("archive-")
        val project = temp.resolve("project")
        SourceTreeGenerator.generate(model(12), project)
        MakeProjectBuilder.build(project)

        val first = ArchivalPackager.create(project, temp.resolve("first.zip"))
        val second = ArchivalPackager.create(project, temp.resolve("second.zip"))
        val extracted = temp.resolve("extracted")
        ArchivalBundleVerifier.extractAndVerify(first.archivePath, extracted)

        assertEquals(first.archiveSha256, second.archiveSha256)
        assertEquals(first.archivePath.readBytes().toList(), second.archivePath.readBytes().toList())
        assertTrue(extracted.resolve("Makefile").exists())
        assertTrue(extracted.resolve("ARCHIVE_README.md").readText().contains("may not be universally equivalent"))
        assertEquals(0, MakeProjectBuilder.build(extracted).returnCode)
    }

    @Test
    fun `verification rejects traversal entries`() {
        val temp = createTempDirectory("archive-traversal-")
        val archive = temp.resolve("bad.zip")
        val bytes = "bad".toByteArray()
        ZipOutputStream(Files.newOutputStream(archive)).use { zip ->
            val crc = CRC32().apply { update(bytes) }
            zip.putNextEntry(ZipEntry("../escape").apply { method = ZipEntry.STORED; size = bytes.size.toLong(); compressedSize = size; this.crc = crc.value })
            zip.write(bytes)
            zip.closeEntry()
        }

        assertFailsWith<IllegalArgumentException> {
            ArchivalBundleVerifier.extractAndVerify(archive, temp.resolve("out"))
        }
        assertTrue(!temp.resolve("escape").exists())
    }

    @Test
    fun `audit keeps mismatched behavior unresolved per source revision`() {
        val temp = createTempDirectory("archive-audit-")
        val project = temp.resolve("project")
        SourceTreeGenerator.generate(model(4), project)
        project.resolve("reports/mismatch.behavior.json").writeText(
            "{\"id\":\"mismatch\",\"sandbox\":\"bubblewrap\",\"networkIsolated\":false,\"matches\":false}",
        )

        val audit = ArchivalProjectAuditor.audit(project)

        assertEquals(false, audit.behaviorMatched)
        assertEquals(listOf("mismatch"), audit.unresolvedBehaviorReportIds)
        assertTrue(audit.moduleRevisionSha256.isNotEmpty())
        assertTrue(project.resolve("reports/archival_audit.json").readText().contains("sourceRevisionSha256"))
    }

    private fun model(size: Int) = RecoveredProgramModel(
        inputSha256 = "archive-fixture",
        functions = (0 until size).map { index ->
            val group = if (index % 2 == 0) "parse" else "render"
            RecoveredFunction("fn_${1000 + index}", "${group}_$index", (0x1000 + index).toULong(), "int ${group}_$index(void)")
        },
    )
}
