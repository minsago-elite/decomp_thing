package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.Test
import kotlin.test.assertEquals

class StableControlFileTest {
    @Test
    fun `stable input hashing checkpoints every MiB`() = inControlTemporaryDirectory { root ->
        val bytes = ByteArray(2 * 1024 * 1024 + 17) { index -> index.toByte() }
        val input = root.resolve("large-control.bin")
        Files.write(input, bytes)
        Files.setPosixFilePermissions(input, PosixFilePermissions.fromString("rw-------"))
        val checkpoints = mutableListOf<String>()

        val digest = StableControlFile.open(input, bytes.size.toLong(), "large control fixture").use { file ->
            file.sha256({ checkpoints += it }, "large control fixture")
        }

        assertEquals(OracleArtifacts.sha256(bytes), digest)
        assertEquals(
            listOf(
                "while hashing large control fixture",
                "while hashing large control fixture",
                "while hashing large control fixture",
                "after hashing large control fixture",
            ),
            checkpoints,
        )
    }
}
