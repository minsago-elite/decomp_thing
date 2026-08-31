package decompengine.oracle.behavior

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.fulltree.StableControlFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermission

class LlvmBehaviorNativeHelperArtifactException(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

/**
 * Build-local integrity result for the static native A15 runtime helper.
 *
 * This verifies the helper/checksum pair and its closed ELF/contract shape. It does not bind the
 * helper to a reviewed behavior corpus, observe a live runtime, authorize START, compare behavior,
 * score fidelity, or authorize a release.
 */
sealed interface LlvmBehaviorNativeHelperArtifact {
    val authority: String
    val protocol: String
    val helperBytes: Long
    val helperSha256: String
    val checksumSha256: String
    val staticElfVerified: Boolean
    val digestPinnedByReference: Boolean
    val startAuthorized: Boolean
    val scoringAuthority: Boolean
    val releaseEligible: Boolean
}

/** Fixed raw-path verifier. No claimed digest, parsed ELF, process, runner, or token is accepted. */
object LlvmBehaviorNativeHelperArtifactVerifier {
    fun verify(helperPath: Path, checksumPath: Path): LlvmBehaviorNativeHelperArtifact =
        VerifiedArtifact(helperPath, checksumPath)

    /* Reflective construction still supplies only the same two raw paths and reruns verification. */
    private class VerifiedArtifact(
        helperPath: Path,
        checksumPath: Path,
    ) : LlvmBehaviorNativeHelperArtifact {
        override val authority = BUILD_LOCAL_AUTHORITY
        override val protocol = HELPER_PROTOCOL
        override val helperBytes: Long
        override val helperSha256: String
        override val checksumSha256: String
        override val staticElfVerified = true
        override val digestPinnedByReference = false
        override val startAuthorized = false
        override val scoringAuthority = false
        override val releaseEligible = false

        init {
            val verified = verifyArtifact(helperPath, checksumPath)
            helperBytes = verified.helperBytes
            helperSha256 = verified.helperSha256
            checksumSha256 = verified.checksumSha256
        }
    }
}

private fun verifyArtifact(helperPath: Path, checksumPath: Path): VerifiedNativeHelper {
    try {
        val helper = helperPath.toAbsolutePath().normalize()
        val checksum = checksumPath.toAbsolutePath().normalize()
        if (helper == checksum) nativeHelperFail("native helper and checksum paths must be distinct")
        if (helper.fileName?.toString() != HELPER_FILE_NAME) {
            nativeHelperFail("native helper must use the fixed installed file name")
        }
        if (checksum.fileName?.toString() != CHECKSUM_FILE_NAME) {
            nativeHelperFail("native helper checksum must use the fixed installed file name")
        }
        if (helper.parent != checksum.parent) {
            nativeHelperFail("native helper and checksum must share one authenticated directory")
        }

        StableControlFile.open(helper, MAXIMUM_HELPER_BYTES, "LLVM behavior native helper").use { helperGuard ->
            StableControlFile.open(
                checksum,
                MAXIMUM_CHECKSUM_BYTES,
                "LLVM behavior native-helper checksum",
            ).use { checksumGuard ->
                requireHelperMode(helper)
                requireChecksumMode(checksum)
                val helperBytes = helperGuard.readExactly(
                    0L,
                    helperGuard.size.toBoundedInt("native helper"),
                    "LLVM behavior native helper",
                )
                val checksumBytes = checksumGuard.readExactly(
                    0L,
                    checksumGuard.size.toBoundedInt("native helper checksum"),
                    "LLVM behavior native-helper checksum",
                )
                val helperSha256 = OracleArtifacts.sha256(helperBytes)
                val expectedChecksum = "$helperSha256  $HELPER_FILE_NAME\n".toByteArray(StandardCharsets.US_ASCII)
                if (!checksumBytes.contentEquals(expectedChecksum)) {
                    nativeHelperFail("native helper checksum does not authenticate the helper bytes")
                }
                verifyStaticElf(helperBytes)
                requireEmbeddedContract(helperBytes)
                helperGuard.verifyUnchanged("LLVM behavior native helper")
                checksumGuard.verifyUnchanged("LLVM behavior native-helper checksum")
                if (!Files.isExecutable(helper)) {
                    nativeHelperFail("native helper lost executable permission during verification")
                }
                return VerifiedNativeHelper(
                    helperBytes = helperGuard.size,
                    helperSha256 = helperSha256,
                    checksumSha256 = OracleArtifacts.sha256(checksumBytes),
                )
            }
        }
    } catch (failure: LlvmBehaviorNativeHelperArtifactException) {
        throw failure
    } catch (failure: Exception) {
        throw LlvmBehaviorNativeHelperArtifactException(
            "LLVM behavior native-helper verification failed: " +
                (failure.message ?: failure.javaClass.simpleName),
            failure,
        )
    }
}

private fun requireHelperMode(path: Path) {
    val permissions = Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS)
    if (PosixFilePermission.OWNER_EXECUTE !in permissions ||
        permissions.any { it == PosixFilePermission.GROUP_WRITE || it == PosixFilePermission.OTHERS_WRITE }
    ) {
        nativeHelperFail("native helper must be owner-executable and not writable by group or others")
    }
}

private fun requireChecksumMode(path: Path) {
    val permissions = Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS)
    if (PosixFilePermission.OWNER_READ !in permissions ||
        permissions.any { it == PosixFilePermission.GROUP_WRITE || it == PosixFilePermission.OTHERS_WRITE }
    ) {
        nativeHelperFail("native helper checksum must be owner-readable and not writable by group or others")
    }
}

private fun verifyStaticElf(bytes: ByteArray) {
    if (bytes.size < ELF64_HEADER_BYTES ||
        bytes[0] != 0x7f.toByte() || bytes[1] != 'E'.code.toByte() ||
        bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte() ||
        bytes[4] != ELF_CLASS_64 || bytes[5] != ELF_LITTLE_ENDIAN || bytes[6] != ELF_CURRENT_VERSION
    ) {
        nativeHelperFail("native helper must be a little-endian ELF64 executable")
    }
    val elf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
    val type = elf.getShort(16).toInt() and 0xffff
    if (type !in setOf(ELF_EXECUTABLE, ELF_SHARED_OBJECT)) {
        nativeHelperFail("native helper ELF type is not executable")
    }
    val expectedMachine = when (System.getProperty("os.arch", "")) {
        "amd64", "x86_64" -> ELF_MACHINE_X86_64
        "aarch64" -> ELF_MACHINE_AARCH64
        else -> nativeHelperFail("native helper verifier does not support this architecture")
    }
    if ((elf.getShort(18).toInt() and 0xffff) != expectedMachine) {
        nativeHelperFail("native helper architecture does not match the host")
    }

    val programOffset = elf.getLong(32)
    val programEntrySize = elf.getShort(54).toInt() and 0xffff
    val programCount = elf.getShort(56).toInt() and 0xffff
    if (programOffset < ELF64_HEADER_BYTES || programEntrySize < ELF64_PROGRAM_HEADER_BYTES || programCount == 0) {
        nativeHelperFail("native helper has an invalid ELF program-header table")
    }
    var executableLoads = 0
    var stackRecords = 0
    repeat(programCount) { index ->
        val offset = checkedElfOffset(programOffset, index, programEntrySize, bytes.size)
        val kind = elf.getInt(offset)
        val flags = elf.getInt(offset + 4)
        when (kind) {
            ELF_PROGRAM_INTERPRETER -> nativeHelperFail("native helper must not contain PT_INTERP")
            ELF_PROGRAM_DYNAMIC -> verifyNoDynamicDependencies(elf, offset, bytes.size)
            ELF_PROGRAM_LOAD -> {
                if (flags and (ELF_FLAG_WRITE or ELF_FLAG_EXECUTE) == (ELF_FLAG_WRITE or ELF_FLAG_EXECUTE)) {
                    nativeHelperFail("native helper contains a writable executable load segment")
                }
                if (flags and ELF_FLAG_EXECUTE != 0) executableLoads++
            }
            ELF_PROGRAM_GNU_STACK -> {
                stackRecords++
                if (flags and ELF_FLAG_EXECUTE != 0) {
                    nativeHelperFail("native helper requests an executable process stack")
                }
            }
        }
    }
    if (executableLoads == 0 || stackRecords != 1) {
        nativeHelperFail("native helper lacks its executable load or unique non-executable stack declaration")
    }
}

private fun checkedElfOffset(base: Long, index: Int, entrySize: Int, totalBytes: Int): Int {
    val offset = try {
        Math.addExact(base, Math.multiplyExact(index.toLong(), entrySize.toLong()))
    } catch (failure: ArithmeticException) {
        nativeHelperFail("native helper ELF program-header offset overflows")
    }
    if (offset < 0L || offset > totalBytes.toLong() - entrySize.toLong()) {
        nativeHelperFail("native helper ELF program headers exceed the artifact")
    }
    return offset.toInt()
}

private fun verifyNoDynamicDependencies(elf: ByteBuffer, programOffset: Int, totalBytes: Int) {
    val dynamicOffset = elf.getLong(programOffset + 8)
    val dynamicSize = elf.getLong(programOffset + 32)
    if (dynamicOffset < 0L || dynamicSize < 0L || dynamicSize % ELF64_DYNAMIC_ENTRY_BYTES != 0L ||
        dynamicOffset > totalBytes.toLong() - dynamicSize
    ) {
        nativeHelperFail("native helper dynamic table is malformed")
    }
    var cursor = dynamicOffset
    var terminated = false
    while (cursor < dynamicOffset + dynamicSize) {
        when (elf.getLong(cursor.toInt())) {
            ELF_DYNAMIC_NULL -> {
                terminated = true
                break
            }
            ELF_DYNAMIC_NEEDED -> nativeHelperFail("native helper must not contain DT_NEEDED")
        }
        cursor += ELF64_DYNAMIC_ENTRY_BYTES
    }
    if (!terminated) nativeHelperFail("native helper dynamic table is unterminated")
}

private fun requireEmbeddedContract(bytes: ByteArray) {
    listOf(
        HELPER_PROTOCOL.toByteArray(StandardCharsets.US_ASCII),
        PREEXEC_FRAME.toByteArray(StandardCharsets.US_ASCII),
        "/case-inputs".toByteArray(StandardCharsets.US_ASCII),
        "/workspace".toByteArray(StandardCharsets.US_ASCII),
        "/case-results".toByteArray(StandardCharsets.US_ASCII),
        "/sys/fs/cgroup".toByteArray(StandardCharsets.US_ASCII),
    ).forEach { marker ->
        if (!bytes.containsSubsequence(marker)) {
            nativeHelperFail("native helper omits a required closed-contract marker")
        }
    }
}

private fun ByteArray.containsSubsequence(needle: ByteArray): Boolean {
    if (needle.isEmpty() || needle.size > size) return false
    for (start in 0..size - needle.size) {
        var matches = true
        for (offset in needle.indices) {
            if (this[start + offset] != needle[offset]) {
                matches = false
                break
            }
        }
        if (matches) return true
    }
    return false
}

private fun Long.toBoundedInt(label: String): Int =
    if (this in 1L..Int.MAX_VALUE.toLong()) toInt() else nativeHelperFail("$label exceeds JVM array bounds")

private fun nativeHelperFail(message: String): Nothing = throw LlvmBehaviorNativeHelperArtifactException(message)

private data class VerifiedNativeHelper(
    val helperBytes: Long,
    val helperSha256: String,
    val checksumSha256: String,
)

private const val BUILD_LOCAL_AUTHORITY = "non-authoritative-build-local-native-helper-v2"
private const val HELPER_PROTOCOL = "decomp-llvm-behavior-helper-v2"
private const val PREEXEC_FRAME = "behavior-preexec-v2:"
private const val HELPER_FILE_NAME = "decomp-llvm-behavior-helper"
private const val CHECKSUM_FILE_NAME = "decomp-llvm-behavior-helper.sha256"
private const val MAXIMUM_HELPER_BYTES = 4L * 1024L * 1024L
private const val MAXIMUM_CHECKSUM_BYTES = 256L
private const val ELF64_HEADER_BYTES = 64
private const val ELF64_PROGRAM_HEADER_BYTES = 56
private const val ELF64_DYNAMIC_ENTRY_BYTES = 16L
private const val ELF_CLASS_64: Byte = 2
private const val ELF_LITTLE_ENDIAN: Byte = 1
private const val ELF_CURRENT_VERSION: Byte = 1
private const val ELF_EXECUTABLE = 2
private const val ELF_SHARED_OBJECT = 3
private const val ELF_MACHINE_X86_64 = 62
private const val ELF_MACHINE_AARCH64 = 183
private const val ELF_PROGRAM_LOAD = 1
private const val ELF_PROGRAM_DYNAMIC = 2
private const val ELF_PROGRAM_INTERPRETER = 3
private const val ELF_PROGRAM_GNU_STACK = 0x6474e551
private const val ELF_FLAG_EXECUTE = 1
private const val ELF_FLAG_WRITE = 2
private const val ELF_DYNAMIC_NULL = 0L
private const val ELF_DYNAMIC_NEEDED = 1L
