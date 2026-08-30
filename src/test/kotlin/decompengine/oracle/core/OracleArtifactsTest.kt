package decompengine.oracle.core

import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import kotlin.io.path.createDirectory
import kotlin.io.path.createSymbolicLinkPointingTo
import kotlin.io.path.createTempDirectory
import kotlin.io.path.listDirectoryEntries
import kotlin.io.path.readBytes
import kotlin.io.path.writeBytes
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse

class OracleArtifactsTest {
    @Test
    fun `publishes replaces and reads exact bounded bytes`() {
        val directory = createTempDirectory("oracle-artifact-").toAbsolutePath().normalize()
        val target = directory.resolve("oracle.json")
        val first = "{\n  \"value\": 1\n}\n".toByteArray()
        val second = "{\n  \"value\": 2\n}\n".toByteArray()

        val firstSnapshot = OracleArtifacts.publishAtomically(target, first)
        assertContentEquals(first, firstSnapshot.bytes)
        assertContentEquals(first, target.readBytes())
        firstSnapshot.bytes[0] = 0
        assertContentEquals(first, firstSnapshot.bytes)

        val secondSnapshot = OracleArtifacts.publishAtomically(target, second)
        assertContentEquals(second, secondSnapshot.bytes)
        assertContentEquals(second, OracleArtifacts.read(target).bytes)
        assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(target))
        assertFalse(directory.listDirectoryEntries().any { it.fileName.toString().startsWith(".decomp-oracle-") })
    }

    @Test
    fun `SHA-256 is lowercase and stable`() {
        assertEquals(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            OracleArtifacts.sha256("abc".toByteArray()),
        )
    }

    @Test
    fun `bounded reads reject oversized files and symbolic links`() {
        val directory = createTempDirectory("oracle-read-").toAbsolutePath().normalize()
        val target = directory.resolve("artifact.json")
        target.writeBytes(byteArrayOf(1, 2, 3, 4))

        assertFailsWith<OracleArtifactException> {
            OracleArtifacts.read(target, OracleArtifactLimits(maximumBytes = 3))
        }

        val link = directory.resolve("link.json")
        link.createSymbolicLinkPointingTo(target)
        assertFailsWith<OracleArtifactException> { OracleArtifacts.read(link) }
    }

    @Test
    fun `publication rejects unsafe targets parents and oversized payloads without mutation`() {
        val directory = createTempDirectory("oracle-publish-reject-").toAbsolutePath().normalize()
        val targetDirectory = directory.resolve("not-a-file").createDirectory()
        assertFailsWith<OracleArtifactException> {
            OracleArtifacts.publishAtomically(targetDirectory, byteArrayOf(1))
        }

        val realParent = createTempDirectory("oracle-real-parent-").toAbsolutePath().normalize()
        val linkedParent = directory.resolve("linked-parent")
        linkedParent.createSymbolicLinkPointingTo(realParent)
        assertFailsWith<OracleArtifactException> {
            OracleArtifacts.publishAtomically(linkedParent.resolve("artifact.json"), byteArrayOf(1))
        }
        assertFalse(Files.exists(realParent.resolve("artifact.json")))

        val oversizedTarget = directory.resolve("oversized.json")
        assertFailsWith<OracleArtifactException> {
            OracleArtifacts.publishAtomically(
                oversizedTarget,
                byteArrayOf(1, 2),
                OracleArtifactLimits(maximumBytes = 1),
            )
        }
        assertFalse(Files.exists(oversizedTarget))
    }

    @Test
    fun `artifact operations reject a parent writable by untrusted principals`() {
        val directory = createTempDirectory("oracle-untrusted-parent-").toAbsolutePath().normalize()
        val target = directory.resolve("artifact.json")
        target.writeBytes("{}\n".toByteArray())
        Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("rwxrwxrwx"))

        assertFailsWith<OracleArtifactException> { OracleArtifacts.read(target) }
        assertFailsWith<OracleArtifactException> { OracleArtifacts.publishAtomically(target, "[]\n".toByteArray()) }
        assertContentEquals("{}\n".toByteArray(), target.readBytes())
    }
}
