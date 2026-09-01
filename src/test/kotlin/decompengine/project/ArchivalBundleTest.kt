package decompengine.project

import decompengine.oracle.fulltree.StableControlFile
import java.io.InputStream
import java.lang.reflect.Modifier
import java.nio.file.Files
import java.nio.file.StandardOpenOption
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
    fun `candidate lineage extraction exposes no arbitrary stream source`() {
        val methods = ArchivalBundleVerifier::class.java.declaredMethods
        assertTrue(methods.none { method ->
            Modifier.isPublic(method.modifiers) &&
                method.parameterTypes.any { parameter -> parameter == InputStream::class.java }
        })
        val guarded = methods.single { method ->
            method.parameterTypes.firstOrNull() == StableControlFile::class.java
        }
        assertTrue(Modifier.isPublic(guarded.modifiers))
        assertTrue(guarded.isSynthetic)
    }

    @Test
    fun `identical source trees produce byte-identical verified archives`() {
        val temp = createTempDirectory("archive-")
        val project = temp.resolve("project")
        SourceTreeGenerator.generate(model(12), project)
        MakeProjectBuilder.build(project)

        val first = ArchivalPackager.create(project, temp.resolve("first.zip"))
        val second = ArchivalPackager.create(project, temp.resolve("second.zip"))
        val extracted = temp.resolve("extracted")
        Files.createDirectories(extracted)
        ArchivalBundleVerifier.extractAndVerify(first.archivePath, extracted)

        assertEquals(first.archiveSha256, second.archiveSha256)
        assertEquals(first.archivePath.readBytes().toList(), second.archivePath.readBytes().toList())
        assertTrue(extracted.resolve("Makefile").exists())
        assertTrue(extracted.resolve("ARCHIVE_README.md").readText().contains("may not be universally equivalent"))
        assertEquals(0, MakeProjectBuilder.build(extracted).returnCode)
    }

    @Test
    fun `separately rooted builds produce identical artifacts contracts and archives`() {
        val temp = createTempDirectory("archive-cross-root-")
        val firstProject = temp.resolve("first/project")
        val secondProject = temp.resolve("a different root/project")
        val recoveredModel = model(12)
        SourceTreeGenerator.generate(recoveredModel, firstProject)
        SourceTreeGenerator.generate(recoveredModel, secondProject)

        MakeProjectBuilder.build(firstProject)
        MakeProjectBuilder.build(secondProject)
        val first = ArchivalPackager.create(firstProject, temp.resolve("first.zip"))
        val second = ArchivalPackager.create(secondProject, temp.resolve("second.zip"))

        assertEquals(
            sha256(firstProject.resolve("build/reconstructed").readBytes()),
            sha256(secondProject.resolve("build/reconstructed").readBytes()),
        )
        assertEquals(
            firstProject.resolve("reports/build_contract.json").readText(),
            secondProject.resolve("reports/build_contract.json").readText(),
        )
        assertEquals(first.archiveSha256, second.archiveSha256)
        assertEquals(first.archivePath.readBytes().toList(), second.archivePath.readBytes().toList())
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
        assertTrue(!temp.resolve("out").exists())
    }

    @Test
    fun `packaging rejects sources that were not used by the recorded successful build`() {
        val temp = createTempDirectory("archive-stale-source-")
        val project = temp.resolve("project")
        SourceTreeGenerator.generate(model(4), project)
        MakeProjectBuilder.build(project)
        val source = project.resolve("src/modules/parse.c")
        val oldHash = sha256(source.readBytes())
        source.writeText(source.readText() + "/* unrecorded edit */\n")
        val newHash = sha256(source.readBytes())
        val sourceManifest = project.resolve("source_tree_manifest.json")
        sourceManifest.writeText(sourceManifest.readText().replace(oldHash, newHash))

        val failure = assertFailsWith<IllegalArgumentException> {
            ArchivalPackager.create(project, temp.resolve("stale.zip"))
        }

        assertTrue(failure.message.orEmpty().contains("build contract does not match the current source inputs"))
        assertTrue(!temp.resolve("stale.zip").exists())
    }

    @Test
    fun `packaging refuses symbolic links into host data`() {
        val temp = createTempDirectory("archive-symlink-")
        val project = temp.resolve("project")
        SourceTreeGenerator.generate(model(4), project)
        MakeProjectBuilder.build(project)
        val outside = temp.resolve("outside-secret").also { it.writeText("do not archive") }
        Files.createSymbolicLink(project.resolve("reports/host-link"), outside)

        val failure = assertFailsWith<IllegalArgumentException> {
            ArchivalPackager.create(project, temp.resolve("linked.zip"))
        }

        assertTrue(failure.message.orEmpty().contains("symbolic link"))
        assertTrue(!temp.resolve("linked.zip").exists())
    }

    @Test
    fun `packaging does not write through archival output symlinks`() {
        val temp = createTempDirectory("archive-output-symlink-")
        val project = temp.resolve("project")
        SourceTreeGenerator.generate(model(4), project)
        MakeProjectBuilder.build(project)
        val outside = temp.resolve("outside-sentinel").also { it.writeText("keep me") }
        Files.createSymbolicLink(project.resolve("ARCHIVE_README.md"), outside)

        val failure = assertFailsWith<IllegalArgumentException> {
            ArchivalPackager.create(project, temp.resolve("linked-output.zip"))
        }

        assertTrue(failure.message.orEmpty().contains("symbolic link"))
        assertEquals("keep me", outside.readText())
        assertTrue(!temp.resolve("linked-output.zip").exists())
    }

    @Test
    fun `packaging atomically replaces hard-linked evidence without changing host files`() {
        val temp = createTempDirectory("archive-output-hardlink-")
        val project = temp.resolve("project")
        SourceTreeGenerator.generate(model(4), project)
        MakeProjectBuilder.build(project)
        val readmeSentinel = temp.resolve("readme-sentinel").also { it.writeText("keep readme") }
        val auditSentinel = temp.resolve("audit-sentinel").also { it.writeText("keep audit") }
        val manifestSentinel = temp.resolve("manifest-sentinel").also { it.writeText("keep manifest") }
        Files.createLink(project.resolve("ARCHIVE_README.md"), readmeSentinel)
        Files.createLink(project.resolve("reports/archival_audit.json"), auditSentinel)
        Files.createLink(project.resolve("ARCHIVE_MANIFEST.sha256"), manifestSentinel)

        val bundle = ArchivalPackager.create(project, temp.resolve("hardlink-safe.zip"))

        assertTrue(bundle.archivePath.exists())
        assertEquals("keep readme", readmeSentinel.readText())
        assertEquals("keep audit", auditSentinel.readText())
        assertEquals("keep manifest", manifestSentinel.readText())
        assertTrue(project.resolve("ARCHIVE_README.md").readText().startsWith("# Reconstructed"))
    }

    @Test
    fun `packaging rejects archive parents that resolve inside the project`() {
        val temp = createTempDirectory("archive-parent-alias-")
        val project = temp.resolve("project")
        SourceTreeGenerator.generate(model(4), project)
        MakeProjectBuilder.build(project)
        val alias = temp.resolve("project-alias")
        Files.createSymbolicLink(alias, project)

        val failure = assertFailsWith<IllegalArgumentException> {
            ArchivalPackager.create(project, alias.resolve("new/output/bundle.zip"))
        }

        assertTrue(failure.message.orEmpty().contains("outside"))
        assertTrue(!project.resolve("new").exists())
    }

    @Test
    fun `packaging rejects non-portable colliding paths`() {
        val temp = createTempDirectory("archive-case-collision-")
        val project = temp.resolve("project")
        SourceTreeGenerator.generate(model(4), project)
        MakeProjectBuilder.build(project)
        Files.createDirectories(project.resolve("notes"))
        project.resolve("notes/Result.txt").writeText("one")
        project.resolve("notes/result.txt").writeText("two")

        val failure = assertFailsWith<IllegalArgumentException> {
            ArchivalPackager.create(project, temp.resolve("collision.zip"))
        }

        assertTrue(failure.message.orEmpty().contains("non-portable colliding path"))
        assertTrue(!temp.resolve("collision.zip").exists())
    }

    @Test
    fun `packaging rejects line-breaking manifest paths`() {
        val temp = createTempDirectory("archive-line-path-")
        val project = temp.resolve("project")
        SourceTreeGenerator.generate(model(4), project)
        MakeProjectBuilder.build(project)
        project.resolve("reports/invalid\nname.txt").writeText("unsafe")

        val failure = assertFailsWith<IllegalArgumentException> {
            ArchivalPackager.create(project, temp.resolve("line-path.zip"))
        }

        assertTrue(failure.message.orEmpty().contains("safe relative path"))
        assertTrue(!temp.resolve("line-path.zip").exists())
    }

    @Test
    fun `packaging rejects a build artifact changed after the successful build`() {
        val temp = createTempDirectory("archive-stale-artifact-")
        val project = temp.resolve("project")
        SourceTreeGenerator.generate(model(4), project)
        MakeProjectBuilder.build(project)
        Files.write(project.resolve("build/reconstructed"), byteArrayOf(0), StandardOpenOption.APPEND)

        val failure = assertFailsWith<IllegalArgumentException> {
            ArchivalPackager.create(project, temp.resolve("stale-artifact.zip"))
        }

        assertTrue(failure.message.orEmpty().contains("artifact does not match"))
        assertTrue(!temp.resolve("stale-artifact.zip").exists())
    }

    @Test
    fun `verification refuses to overwrite a populated target`() {
        val temp = createTempDirectory("archive-populated-target-")
        val project = temp.resolve("project")
        SourceTreeGenerator.generate(model(4), project)
        MakeProjectBuilder.build(project)
        val archive = ArchivalPackager.create(project, temp.resolve("bundle.zip"))
        val target = temp.resolve("target")
        Files.createDirectories(target)
        val sentinel = target.resolve("keep.txt").also { it.writeText("keep") }

        val failure = assertFailsWith<IllegalArgumentException> {
            ArchivalBundleVerifier.extractAndVerify(archive.archivePath, target)
        }

        assertTrue(failure.message.orEmpty().contains("must be empty"))
        assertEquals("keep", sentinel.readText())
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
        inputSha256 = sha256("archive-fixture".toByteArray()),
        functions = (0 until size).map { index ->
            val group = if (index % 2 == 0) "parse" else "render"
            RecoveredFunction("fn_${1000 + index}", "${group}_$index", (0x1000 + index).toULong(), "int ${group}_$index(void)")
        },
    )
}
