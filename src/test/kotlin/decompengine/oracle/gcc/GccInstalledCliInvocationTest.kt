package decompengine.oracle.gcc

import decompengine.oracle.core.OracleJson
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.assertFails
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class GccInstalledCliInvocationTest {
    @Test
    fun `installed launcher reports invalid engine selection without starting analysis`() {
        val evidence = Files.createTempDirectory("installed-gcc-cli-")
        assertEquals(2, invokeInstalledGccCli(listOf("invalid-engine", "unused"), evidence, 30))
        assertTrue(Files.readString(evidence.resolve("launcher-stderr.bin")).contains("expected cc1 or lto1"))
        val result = OracleJson.parseCanonical(Files.readAllBytes(evidence.resolve("launcher-result.json"))).jsonObject
        assertEquals("false", result.getValue("productionVerified").jsonPrimitive.content)
        assertEquals("2", result.getValue("exitCode").jsonPrimitive.content)
        val installation = Path.of(System.getProperty("user.dir"), "build/install/llm_bin_patch")
        val args = listOf("invalid-engine", "unused")
        val checked = verifyInstalledCliEvidence(evidence, args, installation, 2)
        assertEquals("false", checked.getValue("productionVerified").jsonPrimitive.content)
        assertFails { verifyInstalledCliEvidence(evidence, listOf("cc1", "unused"), installation, 2) }
        val stderr = evidence.resolve("launcher-stderr.bin")
        val prior = Files.readAllBytes(stderr)
        Files.write(stderr, prior + byteArrayOf(10))
        assertFails { verifyInstalledCliEvidence(evidence, args, installation, 2) }
        Files.write(stderr, prior)
        assertEquals(checked, verifyInstalledCliEvidence(evidence, args, installation, 2))
    }
}
