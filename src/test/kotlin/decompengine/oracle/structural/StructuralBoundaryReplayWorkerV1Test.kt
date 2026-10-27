package decompengine.oracle.structural

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class StructuralBoundaryReplayWorkerV1Test {
    @Test
    fun `fixture computation replays deterministically without authority`() = withWorkerFixture { fixture ->
        val request = fixture.request()
        val encoded = request.canonicalBytes
        assertContentEquals(encoded, StructuralBoundaryReplayRequestV1.parse(encoded).canonicalBytes)
        StructuralBoundaryReplayWorkerV1.run(request)
        val observation = Files.readAllBytes(fixture.observation)
        val metadata = Files.readAllBytes(fixture.metadata)
        val document = OracleJson.parseCanonical(metadata).jsonObject
        assertEquals("untrusted-worker-computation", document.getValue("authority").jsonPrimitive.content)
        for (flag in listOf("complete", "scored", "productionVerified", "releaseEligible")) {
            assertEquals(JsonPrimitive(false), document.getValue(flag))
        }
        assertEquals(OracleArtifacts.sha256(encoded), document.getValue("requestSha256").jsonPrimitive.content)
        assertEquals(OracleArtifacts.sha256(observation), document.getValue("observationSha256").jsonPrimitive.content)
        assertEquals(JsonPrimitive(observation.size), document.getValue("observationBytes"))
        assertEquals(JsonPrimitive(request.modelSha256), document.getValue("modelSha256"))
        assertEquals(JsonPrimitive(request.functionOracleSha256), document.getValue("functionOracleSha256"))
        val oracle = StructuralRecoveryV1Inputs.loadFunctionOracle(fixture.oracle)
        val independentlyReplayed = StructuralBoundaryReplayV1.observeSelected(oracle, "stripped", fixture.modelBytes,
            request.imageBase, modelLimits = StructuralBoundaryReplayWorkerV1.MODEL_LIMITS)
        assertContentEquals(independentlyReplayed.canonicalBytes, observation)
        Files.delete(fixture.observation)
        Files.delete(fixture.metadata)
        StructuralBoundaryReplayWorkerV1.run(request)
        assertContentEquals(observation, Files.readAllBytes(fixture.observation))
        assertContentEquals(metadata, Files.readAllBytes(fixture.metadata))
    }

    @Test
    fun `launch binding refuses changed requests before computation`() = withWorkerFixture { fixture ->
        val requestPath = fixture.root.resolve("request.json")
        val request = fixture.request()
        Files.write(requestPath, request.canonicalBytes)
        assertFailsWith<IllegalArgumentException> {
            StructuralBoundaryReplayWorkerV1.main(arrayOf(requestPath.toString(), "f".repeat(64)))
        }
        fixture.assertNoOutputs()
        StructuralBoundaryReplayWorkerV1.main(arrayOf(requestPath.toString(), OracleArtifacts.sha256(request.canonicalBytes)))
        assertTrue(Files.isRegularFile(fixture.observation))
        assertTrue(Files.isRegularFile(fixture.metadata))
    }

    @Test
    fun `changed model and oracle bytes cannot be rebound by repeating the input hash`() = withWorkerFixture { fixture ->
        val original = fixture.request()
        Files.write(fixture.model, fixture.modelBytes.toString(Charsets.UTF_8).replace("alpha", "omega").toByteArray())
        assertFailsWith<IllegalArgumentException> { StructuralBoundaryReplayWorkerV1.run(original) }
        fixture.assertNoOutputs()
        Files.write(fixture.model, fixture.modelBytes)
        Files.write(fixture.oracle, fixture.oracleBytes.toString(Charsets.UTF_8).replace("alpha", "omega").toByteArray())
        assertFailsWith<IllegalArgumentException> { StructuralBoundaryReplayWorkerV1.run(original) }
        fixture.assertNoOutputs()
    }

    @Test
    fun `selected input base and declared file sizes are enforced`() = withWorkerFixture { fixture ->
        val mutations = listOf(
            fixture.request(inputSha256 = "f".repeat(64)),
            fixture.request(imageBase = 0x400001UL),
            fixture.request(modelBytes = fixture.modelBytes.size - 1),
            fixture.request(modelBytes = fixture.modelBytes.size + 1),
            fixture.request(functionOracleBytes = fixture.oracleBytes.size - 1),
            fixture.request(functionOracleBytes = fixture.oracleBytes.size + 1),
        )
        for (request in mutations) {
            assertFailsWith<IllegalArgumentException> { StructuralBoundaryReplayWorkerV1.run(request) }
            fixture.assertNoOutputs()
        }
    }

    @Test
    fun `request rejects unknown fields noncanonical scalars and excessive bounds`() = withWorkerFixture { fixture ->
        val atCeiling = fixture.request(modelBytes = StructuralBoundaryReplayRequestV1.MAXIMUM_MODEL_BYTES,
            functionOracleBytes = StructuralBoundaryReplayRequestV1.MAXIMUM_ORACLE_BYTES)
        assertContentEquals(atCeiling.canonicalBytes, StructuralBoundaryReplayRequestV1.parse(atCeiling.canonicalBytes).canonicalBytes)
        val document = OracleJson.parseCanonical(fixture.request().canonicalBytes).jsonObject
        val mutations = listOf(
            JsonObject(document + ("productionVerified" to JsonPrimitive(true))),
            JsonObject(document + ("schemaVersion" to JsonPrimitive(2))),
            JsonObject(document + ("modelBytes" to JsonPrimitive("100"))),
            JsonObject(document + ("modelBytes" to JsonPrimitive(0))),
            JsonObject(document + ("modelBytes" to JsonPrimitive(StructuralBoundaryReplayRequestV1.MAXIMUM_MODEL_BYTES + 1))),
            JsonObject(document + ("functionOracleBytes" to JsonPrimitive(StructuralBoundaryReplayRequestV1.MAXIMUM_ORACLE_BYTES + 1))),
            JsonObject(document + ("imageBase" to JsonPrimitive("0x0400000"))),
            JsonObject(document + ("modelSha256" to JsonPrimitive("A".repeat(64)))),
            JsonObject(document + ("operationRequestSha256" to JsonPrimitive("short"))),
            JsonObject(document + ("fullExportBindingSha256" to JsonPrimitive("F".repeat(64)))),
        )
        for (changed in mutations) {
            assertFailsWith<IllegalArgumentException> { StructuralBoundaryReplayRequestV1.parse(OracleJson.canonicalBytes(changed)) }
        }
        assertFailsWith<IllegalArgumentException> {
            StructuralBoundaryReplayRequestV1.parse(fixture.request().canonicalBytes + '\n'.code.toByte())
        }
        assertFailsWith<IllegalArgumentException> { fixture.request(modelPath = Path.of("relative.json")) }
        assertFailsWith<IllegalArgumentException> { fixture.request(modelPath = fixture.root.resolve("x/../model.json")) }
        assertFailsWith<IllegalArgumentException> { fixture.request(outputDirectory = fixture.root) }
        assertFailsWith<IllegalArgumentException> { fixture.request(modelPath = fixture.oracle) }
        fixture.assertNoOutputs()
    }

    @Test
    fun `indirect input output and request paths fail without output publication`() = withWorkerFixture { fixture ->
        val linkedModel = Files.createSymbolicLink(fixture.root.resolve("model-link.json"), fixture.model)
        assertFailsWith<IllegalArgumentException> { StructuralBoundaryReplayWorkerV1.run(fixture.request(modelPath = linkedModel)) }
        val linkedOracle = Files.createSymbolicLink(fixture.root.resolve("oracle-link.json"), fixture.oracle)
        assertFailsWith<IllegalArgumentException> { StructuralBoundaryReplayWorkerV1.run(fixture.request(functionOraclePath = linkedOracle)) }
        val linkedOutput = Files.createSymbolicLink(fixture.root.resolve("output-link"), fixture.output)
        assertFailsWith<IllegalArgumentException> { StructuralBoundaryReplayWorkerV1.run(fixture.request(outputDirectory = linkedOutput)) }
        val requestPath = Files.write(fixture.root.resolve("request.json"), fixture.request().canonicalBytes)
        val linkedRequest = Files.createSymbolicLink(fixture.root.resolve("request-link.json"), requestPath)
        assertFailsWith<IllegalArgumentException> {
            StructuralBoundaryReplayWorkerV1.main(arrayOf(linkedRequest.toString(), OracleArtifacts.sha256(fixture.request().canonicalBytes)))
        }
        fixture.assertNoOutputs()
    }

    @Test
    fun `prior and partial output is preserved rather than overwritten`() = withWorkerFixture { fixture ->
        val prior = "prior incomplete observation".toByteArray()
        Files.write(fixture.observation, prior)
        assertFailsWith<IllegalArgumentException> { StructuralBoundaryReplayWorkerV1.run(fixture.request()) }
        assertContentEquals(prior, Files.readAllBytes(fixture.observation))
        assertFalse(Files.exists(fixture.metadata))
    }

    @Test
    fun `launcher streams coexist with computation but other output entries refuse`() = withWorkerFixture { fixture ->
        val stdout = fixture.output.resolve("contained-command.stdout")
        val stderr = fixture.output.resolve("contained-command.stderr")
        val contents = "launcher diagnostic\n".toByteArray()
        Files.write(stdout, contents)
        assertFailsWith<IllegalArgumentException> { StructuralBoundaryReplayWorkerV1.run(fixture.request()) }
        Files.createFile(stderr)
        val unrelated = Files.createFile(fixture.output.resolve("unexpected"))
        assertFailsWith<IllegalArgumentException> { StructuralBoundaryReplayWorkerV1.run(fixture.request()) }
        Files.delete(unrelated)
        StructuralBoundaryReplayWorkerV1.run(fixture.request())
        assertContentEquals(contents, Files.readAllBytes(stdout))
        assertEquals(0L, Files.size(stderr))
        assertTrue(Files.isRegularFile(fixture.observation))
        assertTrue(Files.isRegularFile(fixture.metadata))
    }

    @Test
    fun `launcher stream aliases are refused`() = withWorkerFixture { fixture ->
        Files.createSymbolicLink(fixture.output.resolve("contained-command.stdout"), fixture.model)
        Files.createFile(fixture.output.resolve("contained-command.stderr"))
        assertFailsWith<IllegalArgumentException> { StructuralBoundaryReplayWorkerV1.run(fixture.request()) }
        fixture.assertNoOutputs()
    }

    @Test
    fun `output binding rejects rehashed metadata scope and observation substitutions`() = withWorkerFixture { fixture ->
        val request = fixture.request()
        StructuralBoundaryReplayWorkerV1.run(request)
        val observation = Files.readAllBytes(fixture.observation)
        val metadata = Files.readAllBytes(fixture.metadata)
        StructuralBoundaryReplayWorkerV1.verifyOutput(request, observation, metadata)
        val metadataDocument = OracleJson.parseCanonical(metadata).jsonObject
        val observationDocument = OracleJson.parse(observation).jsonObject
        for ((field, value) in listOf(
            "operationRequestSha256" to JsonPrimitive("f".repeat(64)),
            "fullExportBindingSha256" to JsonPrimitive("f".repeat(64)),
            "observationBytes" to JsonPrimitive(observation.size + 1),
            "functionOracleBytes" to JsonPrimitive(fixture.oracleBytes.size + 1),
            "productionVerified" to JsonPrimitive(true),
            "extra" to JsonPrimitive(false),
        )) {
            val changed = OracleJson.canonicalBytes(JsonObject(metadataDocument + (field to value)))
            assertFailsWith<IllegalArgumentException> { StructuralBoundaryReplayWorkerV1.verifyOutput(request, observation, changed) }
        }
        for ((field, value) in listOf(
            "inputSha256" to JsonPrimitive("f".repeat(64)),
            "programModelSha256" to JsonPrimitive("f".repeat(64)),
            "programModelBytes" to JsonPrimitive(fixture.modelBytes.size + 1),
            "functionOracleSha256" to JsonPrimitive("f".repeat(64)),
            "selectedModelImageBase" to JsonPrimitive("0x400001"),
            "twin" to JsonPrimitive("rich"),
            "scored" to JsonPrimitive(true),
            "productionVerified" to JsonPrimitive(true),
        )) {
            val changed = StructuralJsonEncoder(StructuralBoundaryReplayWorkerV1.MAXIMUM_OBSERVATION_BYTES,
                pretty = true, ensureAscii = true).encode(JsonObject(observationDocument + (field to value)))
            val rebound = OracleJson.canonicalBytes(JsonObject(metadataDocument + mapOf(
                "observationSha256" to JsonPrimitive(OracleArtifacts.sha256(changed)),
                "observationBytes" to JsonPrimitive(changed.size),
            )))
            assertFailsWith<IllegalArgumentException> { StructuralBoundaryReplayWorkerV1.verifyOutput(request, changed, rebound) }
        }
        val noncanonical = observation + '\n'.code.toByte()
        val rebound = OracleJson.canonicalBytes(JsonObject(metadataDocument + mapOf(
            "observationSha256" to JsonPrimitive(OracleArtifacts.sha256(noncanonical)),
            "observationBytes" to JsonPrimitive(noncanonical.size),
        )))
        assertFailsWith<IllegalArgumentException> { StructuralBoundaryReplayWorkerV1.verifyOutput(request, noncanonical, rebound) }
    }
}

private class BoundaryWorkerFixture(val root: Path) {
    val modelBytes = workerResource("structural-boundary-replay-v1/rich-model.json")
        .toString(Charsets.UTF_8).replace("1".repeat(64), "2".repeat(64)).toByteArray()
    val oracleBytes = workerResource("structural-v1/function-oracle.json")
    val model: Path = Files.write(root.resolve("model.json"), modelBytes)
    val oracle: Path = Files.write(root.resolve("oracle.json"), oracleBytes)
    val output: Path = Files.createDirectory(root.resolve("output"))
    val observation: Path = output.resolve(StructuralBoundaryReplayWorkerV1.OBSERVATION_NAME)
    val metadata: Path = output.resolve(StructuralBoundaryReplayWorkerV1.METADATA_NAME)

    fun request(
        modelPath: Path = model,
        modelBytes: Int = this.modelBytes.size,
        inputSha256: String = "2".repeat(64),
        functionOraclePath: Path = oracle,
        functionOracleBytes: Int = oracleBytes.size,
        imageBase: ULong = 0x400000UL,
        outputDirectory: Path = output,
    ) = StructuralBoundaryReplayRequestV1(modelPath, modelBytes, OracleArtifacts.sha256(this.modelBytes), inputSha256,
        functionOraclePath, functionOracleBytes, OracleArtifacts.sha256(oracleBytes), imageBase, outputDirectory,
        "3".repeat(64), "4".repeat(64))

    fun assertNoOutputs() {
        assertFalse(Files.exists(observation))
        assertFalse(Files.exists(metadata))
    }
}

private fun workerResource(name: String): ByteArray = StructuralBoundaryReplayWorkerV1Test::class.java
    .getResourceAsStream("/oracle/$name")!!.use { it.readBytes() }

private fun withWorkerFixture(block: (BoundaryWorkerFixture) -> Unit) {
    val parent = Files.createDirectories(Path.of("build/test-tmp").toAbsolutePath().normalize()).toRealPath()
    val root = Files.createTempDirectory(parent, "boundary-worker-")
    try {
        block(BoundaryWorkerFixture(root))
    } finally {
        root.toFile().deleteRecursively()
    }
}
