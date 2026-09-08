package decompengine.oracle.gcc

import decompengine.oracle.core.OracleJson
import java.nio.file.Files
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
    }
}
