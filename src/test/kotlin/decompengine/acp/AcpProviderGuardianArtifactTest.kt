package decompengine.acp

import java.io.IOException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AcpProviderGuardianArtifactTest {
    @Test
    fun `Gradle-built guardian is authenticated and rejects a missing protocol invocation`() {
        val executable = productionAcpProviderGuardian()
        val artifact = AcpProviderGuardianArtifact.authenticate(executable, productionAcpProviderGuardianChecksum(), productionAcpProviderGuardianSha256())
        assertEquals(executable, artifact.executable)
        assertEquals(sha256(Files.readAllBytes(executable)), artifact.executableSha256)
        assertEquals(calculateAcpRuntimeManifestSha256(executable), artifact.runtimeManifestSha256)
        assertFalse(Files.isSymbolicLink(executable))
        val process = ProcessBuilder(executable.toString()).also { it.environment().clear() }.start()
        try {
            process.outputStream.close()
            val exited = process.waitFor(5, TimeUnit.SECONDS)
            if (!exited) {
                process.destroyForcibly()
                assertTrue(process.waitFor(2, TimeUnit.SECONDS), "guardian probe cleanup was not observed")
            }
            assertTrue(exited, "guardian did not reject a missing protocol invocation")
            assertEquals(120, process.exitValue())
            assertTrue(process.inputStream.readBytes().isEmpty())
            assertTrue(process.errorStream.readBytes().isEmpty())
        } finally {
            if (process.isAlive) {
                process.destroyForcibly()
                assertTrue(process.waitFor(2, TimeUnit.SECONDS), "guardian probe cleanup was not observed")
            }
            process.inputStream.close()
            process.errorStream.close()
        }
    }

    @Test
    fun `reject tampered executable before it can be launched`() = withArtifacts { executable, checksum ->
        val bytes = Files.readAllBytes(executable)
        bytes[bytes.lastIndex] = (bytes.last().toInt() xor 1).toByte()
        Files.write(executable, bytes)
        assertIntegrityFailure { AcpProviderGuardianArtifact.authenticate(executable, checksum, productionAcpProviderGuardianSha256()) }
    }

    @Test
    fun `reject paired executable and checksum replacement against the trusted commitment`() = withArtifacts { executable, checksum ->
        val bytes = Files.readAllBytes(executable)
        bytes[bytes.lastIndex] = (bytes.last().toInt() xor 1).toByte()
        Files.write(executable, bytes)
        writeChecksum(executable, checksum)
        // The replacement remains a static ELF and has a matching adjacent checksum.
        verifyStaticAcpProviderGuardian(bytes, sha256(bytes), 0x1ed)
        assertIntegrityFailure {
            AcpProviderGuardianArtifact.authenticate(executable, checksum, productionAcpProviderGuardianSha256())
        }
    }

    @Test
    fun `reject dynamic executable even when its checksum matches`() = withArtifacts { executable, checksum ->
        Files.copy(Path.of("/usr/bin/true"), executable, java.nio.file.StandardCopyOption.REPLACE_EXISTING)
        Files.setPosixFilePermissions(executable, PosixFilePermissions.fromString("rwxr-xr-x"))
        writeChecksum(executable, checksum)
        assertIntegrityFailure { AcpProviderGuardianArtifact.authenticate(executable, checksum, sha256(Files.readAllBytes(executable))) }
    }

    @Test
    fun `reject missing executable and missing checksum`() = withArtifacts { executable, checksum ->
        assertIntegrityFailure { AcpProviderGuardianArtifact.authenticate(executable.resolveSibling("missing"), checksum, productionAcpProviderGuardianSha256()) }
        assertIntegrityFailure { AcpProviderGuardianArtifact.authenticate(executable, checksum.resolveSibling("missing"), productionAcpProviderGuardianSha256()) }
    }

    @Test
    fun `reject malformed checksum rather than accepting its digest prefix`() = withArtifacts { executable, checksum ->
        Files.writeString(checksum, sha256(Files.readAllBytes(executable)) + "  another-executable\n")
        assertIntegrityFailure { AcpProviderGuardianArtifact.authenticate(executable, checksum, productionAcpProviderGuardianSha256()) }
    }

    @Test
    fun `reject symlink substitutions`() = withArtifacts { executable, checksum ->
        val alias = executable.resolveSibling("alias")
        Files.createSymbolicLink(alias, executable.fileName)
        assertIntegrityFailure { AcpProviderGuardianArtifact.authenticate(alias, checksum, productionAcpProviderGuardianSha256()) }
        val checksumAlias = executable.resolveSibling("checksum-alias")
        Files.createSymbolicLink(checksumAlias, checksum.fileName)
        assertIntegrityFailure { AcpProviderGuardianArtifact.authenticate(executable, checksumAlias, productionAcpProviderGuardianSha256()) }
    }

    @Test
    fun `reject executable and checksum modes that differ from the packaged modes`() = withArtifacts { executable, checksum ->
        Files.setPosixFilePermissions(executable, PosixFilePermissions.fromString("rwxrwxr-x"))
        assertIntegrityFailure { AcpProviderGuardianArtifact.authenticate(executable, checksum, productionAcpProviderGuardianSha256()) }
        Files.setPosixFilePermissions(executable, PosixFilePermissions.fromString("rwxr-xr-x"))
        Files.setPosixFilePermissions(checksum, PosixFilePermissions.fromString("rw-rw-r--"))
        assertIntegrityFailure { AcpProviderGuardianArtifact.authenticate(executable, checksum, productionAcpProviderGuardianSha256()) }
    }

    @Test
    fun `reject wrong architecture through the production static verifier`() {
        val bytes = Files.readAllBytes(productionAcpProviderGuardian())
        val elf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        elf.putShort(18, if (elf.getShort(18).toInt() == 62) 183.toShort() else 62.toShort())
        assertIntegrityFailure { verifyStaticAcpProviderGuardian(bytes, sha256(bytes), 0x1ed) }
    }

    @Test
    fun `reject PT_INTERP through the production static verifier`() {
        val bytes = staticElfWithProgramHeader(3)
        assertIntegrityFailure { verifyStaticAcpProviderGuardian(bytes, sha256(bytes), 0x1ed) }
    }

    @Test
    fun `reject DT_NEEDED through the production static verifier`() {
        val bytes = staticElfWithProgramHeader(2)
        val elf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        elf.putLong(64 + 8, 120L)
        elf.putLong(64 + 32, 32L)
        elf.putLong(120, 1L)
        assertIntegrityFailure { verifyStaticAcpProviderGuardian(bytes, sha256(bytes), 0x1ed) }
    }

    @Test
    fun `reject malformed ELF with the fixed production-verifier diagnostic`() {
        val empty = byteArrayOf()
        assertIntegrityFailure { verifyStaticAcpProviderGuardian(empty, sha256(empty), 0x1ed) }
        val bytes = staticElfWithProgramHeader(1)
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).putLong(32, Long.MAX_VALUE)
        assertIntegrityFailure { verifyStaticAcpProviderGuardian(bytes, sha256(bytes), 0x1ed) }
    }

    @Test
    fun `reject oversized checksum and artifact bytes before release`() = withArtifacts { executable, checksum ->
        Files.write(checksum, ByteArray(96))
        assertIntegrityFailure { AcpProviderGuardianArtifact.authenticate(executable, checksum, productionAcpProviderGuardianSha256()) }
        Files.write(executable, ByteArray(4 * 1024 * 1024 + 1))
        writeChecksum(executable, checksum)
        assertIntegrityFailure { AcpProviderGuardianArtifact.authenticate(executable, checksum, productionAcpProviderGuardianSha256()) }
    }

    private fun withArtifacts(test: (Path, Path) -> Unit) {
        val parent = Path.of(System.getProperty("user.dir")).toAbsolutePath().normalize()
            .resolve("build/provider-guardian-artifact-tests")
        Files.createDirectories(parent)
        val root = Files.createTempDirectory(parent, "artifact-")
        try {
            val executable = root.resolve("decomp-acp-provider-guardian")
            val checksum = root.resolve("decomp-acp-provider-guardian.sha256")
            Files.copy(productionAcpProviderGuardian(), executable)
            Files.setPosixFilePermissions(executable, PosixFilePermissions.fromString("rwxr-xr-x"))
            writeChecksum(executable, checksum)
            test(executable, checksum)
        } finally {
            Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }

    private fun assertIntegrityFailure(action: () -> Unit) {
        val failure = assertFailsWith<IOException>(block = action)
        assertEquals("ACP provider guardian artifact integrity check failed", failure.message)
        assertEquals(null, failure.cause)
    }

    private fun writeChecksum(executable: Path, checksum: Path) {
        Files.writeString(checksum, sha256(Files.readAllBytes(executable)) + "  decomp-acp-provider-guardian\n")
        Files.setPosixFilePermissions(checksum, PosixFilePermissions.fromString("rw-r--r--"))
    }

    private fun staticElfWithProgramHeader(type: Int): ByteArray = ByteArray(152).also { bytes ->
        bytes[0] = 0x7f
        bytes[1] = 'E'.code.toByte()
        bytes[2] = 'L'.code.toByte()
        bytes[3] = 'F'.code.toByte()
        bytes[4] = 2
        bytes[5] = 1
        val elf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        elf.putShort(18, when (System.getProperty("os.arch")) {
            "amd64", "x86_64" -> 62.toShort()
            "aarch64" -> 183.toShort()
            else -> error("unsupported test architecture")
        })
        elf.putLong(32, 64L)
        elf.putShort(54, 56)
        elf.putShort(56, 1)
        elf.putInt(64, type)
    }

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes)
        .joinToString("") { byte -> "%02x".format(byte) }
}

internal fun productionAcpProviderGuardian(): Path = requiredGuardianArtifact("decompengine.acp.providerGuardianExecutable")

private fun productionAcpProviderGuardianChecksum(): Path = requiredGuardianArtifact("decompengine.acp.providerGuardianChecksum")

private fun productionAcpProviderGuardianSha256(): String = requireNotNull(
    System.getProperty("decompengine.acp.providerGuardianExpectedSha256"),
) { "trusted provider guardian digest was not supplied by the verified Gradle producer" }.also {
    require(it.matches(Regex("[0-9a-f]{64}"))) { "trusted provider guardian digest is noncanonical" }
}


private fun requiredGuardianArtifact(property: String): Path {
    val path = Path.of(requireNotNull(System.getProperty(property)) {
        "provider guardian artifact was not supplied by the Gradle production build"
    })
    require(path.isAbsolute && path == path.normalize() && Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
        "provider guardian artifact is unavailable"
    }
    return path
}
