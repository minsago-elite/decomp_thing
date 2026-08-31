package decompengine.oracle.behavior

import java.lang.reflect.Modifier
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class LlvmBehaviorNativeHelperArtifactTest {
    @Test
    fun `Gradle-built native helper has build-local integrity without START or release authority`() {
        val artifact = LlvmBehaviorNativeHelperArtifactVerifier.verify(productionHelper(), productionChecksum())

        assertEquals("non-authoritative-build-local-native-helper-v2", artifact.authority)
        assertEquals("decomp-llvm-behavior-helper-v2", artifact.protocol)
        assertTrue(artifact.helperBytes in 64L..(4L * 1024L * 1024L))
        assertTrue(artifact.helperSha256.matches(Regex("[0-9a-f]{64}")))
        assertTrue(artifact.checksumSha256.matches(Regex("[0-9a-f]{64}")))
        assertTrue(artifact.staticElfVerified)
        assertFalse(artifact.digestPinnedByReference)
        assertFalse(artifact.startAuthorized)
        assertFalse(artifact.scoringAuthority)
        assertFalse(artifact.releaseEligible)
    }

    @Test
    fun `non-ELF mutation is rejected even when the adjacent checksum is rewritten`() = withArtifactCopy { helper, checksum ->
        val bytes = Files.readAllBytes(helper)
        bytes[0] = 0
        Files.write(helper, bytes)
        writeChecksum(helper, checksum)

        val failure = assertFailsWith<LlvmBehaviorNativeHelperArtifactException> {
            LlvmBehaviorNativeHelperArtifactVerifier.verify(helper, checksum)
        }
        assertTrue(failure.message.orEmpty().contains("ELF64"))
    }

    @Test
    fun `stale malformed and renamed checksum bindings are rejected`() = withArtifactCopy { helper, checksum ->
        val original = Files.readString(checksum)
        Files.writeString(checksum, original.replace("  ", " "))
        assertFailsWith<LlvmBehaviorNativeHelperArtifactException> {
            LlvmBehaviorNativeHelperArtifactVerifier.verify(helper, checksum)
        }

        Files.writeString(checksum, original)
        val renamed = checksum.resolveSibling("unexpected.sha256")
        Files.move(checksum, renamed)
        assertFailsWith<LlvmBehaviorNativeHelperArtifactException> {
            LlvmBehaviorNativeHelperArtifactVerifier.verify(helper, renamed)
        }
    }

    @Test
    fun `symlink helper and untrusted writable parent are rejected`() {
        val root = createTempDirectory("llvm-behavior-helper-symlink-")
        try {
            val target = root.resolve("target")
            Files.copy(productionHelper(), target)
            Files.setPosixFilePermissions(target, PosixFilePermissions.fromString("rwxr-xr-x"))
            val helper = root.resolve(HELPER_NAME)
            Files.createSymbolicLink(helper, target.fileName)
            val checksum = root.resolve(CHECKSUM_NAME)
            writeChecksum(target, checksum, HELPER_NAME)
            assertFailsWith<LlvmBehaviorNativeHelperArtifactException> {
                LlvmBehaviorNativeHelperArtifactVerifier.verify(helper, checksum)
            }

            Files.delete(helper)
            Files.move(target, helper)
            Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwxrwx---"))
            assertFailsWith<LlvmBehaviorNativeHelperArtifactException> {
                LlvmBehaviorNativeHelperArtifactVerifier.verify(helper, checksum)
            }
        } finally {
            root.toFile().deleteRecursively()
        }
    }

    @Test
    fun `JVM implementation constructors accept only raw paths and rerun verification`() {
        val implementations = LlvmBehaviorNativeHelperArtifactVerifier::class.java.declaredClasses
            .filter { LlvmBehaviorNativeHelperArtifact::class.java.isAssignableFrom(it) }
        assertEquals(1, implementations.size)
        val constructors = implementations.single().declaredConstructors
        assertEquals(1, constructors.size)
        assertTrue(constructors.single().parameterTypes.contentEquals(arrayOf(Path::class.java, Path::class.java)))
        assertTrue(Modifier.isPrivate(implementations.single().modifiers))

        constructors.single().isAccessible = true
        val failure = assertFailsWith<Exception> {
            constructors.single().newInstance(
                Path.of("/definitely-absent/decomp-helper"),
                Path.of("/definitely-absent/decomp-helper.sha256"),
            )
        }
        assertTrue(failure.cause is LlvmBehaviorNativeHelperArtifactException)
    }

    private fun withArtifactCopy(block: (Path, Path) -> Unit) {
        val root = createTempDirectory("llvm-behavior-helper-artifact-")
        try {
            val helper = root.resolve(HELPER_NAME)
            val checksum = root.resolve(CHECKSUM_NAME)
            Files.copy(productionHelper(), helper, StandardCopyOption.COPY_ATTRIBUTES)
            Files.copy(productionChecksum(), checksum, StandardCopyOption.COPY_ATTRIBUTES)
            Files.setPosixFilePermissions(helper, PosixFilePermissions.fromString("rwxr-xr-x"))
            Files.setPosixFilePermissions(checksum, PosixFilePermissions.fromString("rw-r--r--"))
            block(helper, checksum)
        } finally {
            root.toFile().deleteRecursively()
        }
    }

    private fun writeChecksum(helper: Path, checksum: Path, fileName: String = HELPER_NAME) {
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(Files.readAllBytes(helper))
            .joinToString("") { "%02x".format(it) }
        Files.writeString(checksum, "$digest  $fileName\n")
        Files.setPosixFilePermissions(checksum, PosixFilePermissions.fromString("rw-r--r--"))
    }

    private fun productionHelper(): Path = requiredArtifact(
        "decompengine.oracle.behavior.nativeHelperExecutable",
        "production LLVM behavior helper",
    )

    private fun productionChecksum(): Path = requiredArtifact(
        "decompengine.oracle.behavior.nativeHelperChecksum",
        "production LLVM behavior-helper checksum",
    )

    private fun requiredArtifact(property: String, label: String): Path {
        val configured = requireNotNull(System.getProperty(property)) { "$label was not supplied by Gradle" }
        val path = Path.of(configured).toAbsolutePath().normalize()
        require(path == Path.of(configured)) { "$label path must be absolute and normalized" }
        require(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) { "$label is unavailable: $path" }
        return path
    }

    private companion object {
        const val HELPER_NAME = "decomp-llvm-behavior-helper"
        const val CHECKSUM_NAME = "decomp-llvm-behavior-helper.sha256"
    }
}
