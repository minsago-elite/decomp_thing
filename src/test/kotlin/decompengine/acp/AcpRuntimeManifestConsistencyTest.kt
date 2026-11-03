package decompengine.acp

import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class AcpRuntimeManifestConsistencyTest {
    private fun ordinaryRootOwnedFile(): Path {
        val source = Path.of("/usr/bin/true")
        AcpLiveContractHost.requireCapability(Files.isRegularFile(source) && !Files.isWritable(source),
            { "runtime manifest consistency requires an ordinary immutable root-owned file" })
        return source
    }

    @Test
    fun `security screening of an unrelated same size file preserves its provisioned manifest`() {
        val source = ordinaryRootOwnedFile()
        val limits = AcpRuntimeClosureLimits()
        val expected = calculateAcpRuntimeManifestSha256(source, limits)
        val unrelated = ForbiddenRuntimeFile(-1, -1, Files.size(source), "0".repeat(64))
        val screened = buildRuntimeManifest(source, limits, setOf(unrelated))
        assertTrue(screened.recursivelyRootOwnedAndImmutable)
        assertEquals(expected, screened.manifestSha256)
    }

    @Test
    fun `manifest stability preserves the forbidden content check`() {
        val source = ordinaryRootOwnedFile()
        val digest = MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(source))
            .joinToString("") { "%02x".format(it) }
        val matchingContent = ForbiddenRuntimeFile(-1, -1, Files.size(source), digest)
        assertFailsWith<IOException> { buildRuntimeManifest(source, AcpRuntimeClosureLimits(), setOf(matchingContent)) }
    }

    @Test
    fun `pinned descriptor change time detects same size edits after mtime restoration`() {
        val source = Files.createTempFile(Path.of("build"), "acp-pinned-identity-", ".bin")
        try {
            val original = byteArrayOf(1, 2, 3, 4)
            Files.write(source, original)
            val descriptor = LinuxFilesystemSyscalls.openAbsolutePathOrNull(source)
                ?: error("temporary pinned identity fixture disappeared")
            descriptor.use {
                val before = readPinnedDescriptorIdentity(descriptor)
                val originalModified = Files.getLastModifiedTime(source)
                Files.write(source, byteArrayOf(5, 6, 7, 8))
                Files.setLastModifiedTime(source, originalModified)
                val after = readPinnedDescriptorIdentity(descriptor)
                assertEquals(before.modifiedMillis, after.modifiedMillis)
                assertNotEquals(before.changedTime, after.changedTime)
            }
        } finally {
            Files.deleteIfExists(source)
        }
    }
}
