package decompengine.oracle.gcc

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.project.ProgramAnalysisResult
import decompengine.project.ProgramModelJson
import decompengine.project.sha256
import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.GZIPInputStream
import kotlinx.serialization.json.*
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull

class GccProgramAnalysisResultCompatibilityTest {
    @Test
    fun `bounded transport preserves retained real model bytes as offline evidence only`() {
        val directory = Path.of("oracle/gcc/16.2.0/production-function-replay")
        val manifestBytes = Files.newInputStream(directory.resolve("evidence.json")).use { it.readNBytes(64 * 1024 + 1) }
        require(manifestBytes.size <= 64 * 1024)
        val manifest = OracleJson.parse(manifestBytes, StrictJsonLimits(
            maximumInputBytes = 64 * 1024, maximumCanonicalBytes = 64 * 1024,
        )).jsonObject
        val modelEntry = manifest.getValue("payloads").jsonArray.map { it.jsonObject }
            .single { it.getValue("role").jsonPrimitive.content == "model" }
        val modelBytes = 8_819_191
        val gzipBytes = 992_357
        val modelSha256 = "0c8f89f9346782f4bcc9ee4d421200aa7ba29122ce762eb4b267b64b0496d1c1"
        val gzipSha256 = "878295e2583dd11537b9858c0fa174b7b2f7265d4422e21f1849935cad1689bf"
        assertEquals("model.json.gz", modelEntry.getValue("path").jsonPrimitive.content)
        assertEquals(modelBytes, modelEntry.getValue("bytes").jsonPrimitive.int)
        assertEquals(gzipBytes, modelEntry.getValue("gzipBytes").jsonPrimitive.int)
        assertEquals(modelSha256, modelEntry.getValue("sha256").jsonPrimitive.content)
        assertEquals(gzipSha256, modelEntry.getValue("gzipSha256").jsonPrimitive.content)
        require(modelBytes in 1..ProgramAnalysisResult.MAXIMUM_MODEL_BYTES)
        val compressed = Files.newInputStream(directory.resolve("model.json.gz")).use { it.readNBytes(gzipBytes + 1) }
        assertEquals(gzipBytes, compressed.size)
        assertEquals(gzipSha256, sha256(compressed))
        val original = GZIPInputStream(compressed.inputStream()).use { it.readNBytes(modelBytes + 1) }
        assertEquals(modelBytes, original.size)
        assertEquals(modelSha256, sha256(original))

        val retainedModel = ProgramModelJson.readCanonical(original)
        assertEquals(3_384, retainedModel.functions.size)
        val result = ProgramAnalysisResult.fromModel(retainedModel, maximumBytes = original.size)

        assertContentEquals(original, result.canonicalModelBytes)
        assertEquals(modelBytes.toLong(), result.modelBytes)
        assertEquals(modelSha256, result.modelSha256)
        // These pinned bytes test format compatibility; retained receipts cannot issue live authority.
        assertNull(result.selectedStructuralInputs)
    }
}
