package decompengine.acp

import java.io.IOException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributes
import java.security.MessageDigest

/**
 * Provisioning commitment for the packaged guardian. It neither launches a process nor admits a
 * provider. The expected digest must come from the owner's authenticated configuration commitment,
 * not the adjacent checksum. The sandbox owner must pin these bytes again before execution.
 */
internal class AcpProviderGuardianArtifact private constructor(
    val executable: Path,
    val executableSha256: String,
    val runtimeManifestSha256: String,
) {
    companion object {
        internal fun authenticate(executable: Path, checksum: Path, trustedExecutableSha256: String): AcpProviderGuardianArtifact {
            try {
                require(trustedExecutableSha256.matches(Regex("[0-9a-f]{64}")))
                val executableIdentity = artifactIdentity(executable, MAXIMUM_GUARDIAN_BYTES, 0x1ed)
                val checksumIdentity = artifactIdentity(checksum, GUARDIAN_CHECKSUM_BYTES, 0x1a4)
                require(checksumIdentity.size() == GUARDIAN_CHECKSUM_BYTES.toLong())
                val checksumBytes = boundedArtifactRead(checksum, GUARDIAN_CHECKSUM_BYTES)
                val expected = checksumBytes.toString(Charsets.US_ASCII)
                require(expected.matches(Regex("[0-9a-f]{64}  decomp-acp-provider-guardian\n")))
                val bytes = boundedArtifactRead(executable, MAXIMUM_GUARDIAN_BYTES)
                val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
                    .joinToString("") { byte -> "%02x".format(byte) }
                require(digest == trustedExecutableSha256 && expected == "$digest  decomp-acp-provider-guardian\n")
                verifyStaticAcpProviderGuardian(bytes, digest, 0x1ed)
                val manifest = calculateAcpRuntimeManifestSha256(executable)
                require(sameArtifactIdentity(executableIdentity,
                    artifactIdentity(executable, MAXIMUM_GUARDIAN_BYTES, 0x1ed)))
                require(sameArtifactIdentity(checksumIdentity,
                    artifactIdentity(checksum, GUARDIAN_CHECKSUM_BYTES, 0x1a4)))
                require(boundedArtifactRead(executable, MAXIMUM_GUARDIAN_BYTES).contentEquals(bytes))
                require(boundedArtifactRead(checksum, GUARDIAN_CHECKSUM_BYTES).contentEquals(checksumBytes))
                return AcpProviderGuardianArtifact(executable, digest, manifest)
            } catch (_: Exception) {
                throw IOException("ACP provider guardian artifact integrity check failed")
            }
        }
    }
}

private fun artifactIdentity(path: Path, maximumBytes: Int, expectedMode: Int): BasicFileAttributes {
    require(path.isAbsolute && path == path.normalize() && path == path.toRealPath())
    val attributes = Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
    require(attributes.isRegularFile && attributes.size() in 1L..maximumBytes.toLong() && attributes.fileKey() != null)
    // Include setuid/setgid/sticky bits; POSIX permissions alone do not expose them.
    require((Files.getAttribute(path, "unix:mode", LinkOption.NOFOLLOW_LINKS) as Number).toInt() and 0xfff == expectedMode)
    return attributes
}

private fun sameArtifactIdentity(before: BasicFileAttributes, after: BasicFileAttributes): Boolean =
    before.fileKey() == after.fileKey() && before.size() == after.size() &&
        before.lastModifiedTime() == after.lastModifiedTime() && before.creationTime() == after.creationTime()

private fun boundedArtifactRead(path: Path, maximumBytes: Int): ByteArray =
    Files.newInputStream(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS).use { stream ->
        val bytes = stream.readNBytes(maximumBytes + 1)
        require(bytes.size <= maximumBytes)
        bytes
    }

private const val MAXIMUM_GUARDIAN_BYTES = 4 * 1024 * 1024
private const val GUARDIAN_CHECKSUM_BYTES = 95
