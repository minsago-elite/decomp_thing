package decompengine.acp

import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AcpGateHelperArtifactTest {
    @Test
    fun `Gradle-built gate helper is the authenticated fail-closed production artifact`() {
        val helper = productionAcpGateHelper()
        val checksum = productionAcpGateHelperChecksum()

        assertFalse(Files.isSymbolicLink(helper))
        assertTrue(Files.isRegularFile(helper, LinkOption.NOFOLLOW_LINKS))
        assertTrue(Files.isExecutable(helper))
        assertEquals(0x1ed, (Files.getAttribute(helper, "unix:mode") as Number).toInt() and 0x1ff)
        assertTrue(Files.size(helper) in 64L..(4L * 1024 * 1024))
        val bytes = Files.readAllBytes(helper)
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(bytes)
            .joinToString("") { byte -> "%02x".format(byte) }
        assertEquals("$digest  decomp-acp-gate-helper\n", Files.readString(checksum))
        assertTrue(calculateAcpRuntimeManifestSha256(helper).matches(Regex("[0-9a-f]{64}")))

        val process = ProcessBuilder(helper.toString()).also { builder ->
            builder.environment().clear()
        }.start()
        process.outputStream.close()
        val exited = process.waitFor(5, TimeUnit.SECONDS)
        if (!exited) {
            process.destroyForcibly()
            process.waitFor(2, TimeUnit.SECONDS)
        }
        assertTrue(exited, "production gate helper did not reject a missing protocol invocation")
        assertEquals(120, process.exitValue())
    }
}

internal fun productionAcpGateHelper(): Path = requiredProductionArtifact(
    "decompengine.acp.gateHelperExecutable",
    "production ACP gate helper",
)

private fun productionAcpGateHelperChecksum(): Path = requiredProductionArtifact(
    "decompengine.acp.gateHelperChecksum",
    "production ACP gate-helper checksum",
)

private fun requiredProductionArtifact(property: String, label: String): Path {
    val configured = requireNotNull(System.getProperty(property)) {
        "$label was not supplied by the Gradle production build"
    }
    val path = Path.of(configured).toAbsolutePath().normalize()
    require(path == Path.of(configured)) { "$label path must be absolute and normalized" }
    require(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) { "$label is unavailable: $path" }
    return path
}
