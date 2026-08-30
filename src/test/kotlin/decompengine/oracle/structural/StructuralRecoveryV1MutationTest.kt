package decompengine.oracle.structural

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class StructuralRecoveryV1MutationTest {
    @Test
    fun `boundary score is authenticated against the upstream function oracle`() = withStructuralFixture { fixture ->
        val functionOracle = parseObject(fixture.path("function-oracle.json"))
        val functions = (functionOracle.getValue("functions") as JsonArray).toMutableList()
        val first = functions.first() as JsonObject
        functions[0] = JsonObject(first + ("rva" to JsonPrimitive("0x11")))
        writeCanonical(fixture.path("function-oracle.json"), JsonObject(functionOracle + ("functions" to JsonArray(functions))))

        val target = StructuralRecoveryV1Inputs.loadTargetAbi(fixture.path("target-abi.json"))
        val mutatedOracle = StructuralRecoveryV1Inputs.loadFunctionOracle(fixture.path("function-oracle.json"))
        assertFailsWith<StructuralRecoveryV1Exception> {
            StructuralRecoveryV1Inputs.loadBoundaryMapping(
                fixture.path("boundary-score.json"),
                "rich",
                target,
                mutatedOracle,
            )
        }

        copyResource("function-oracle.json", fixture.path("function-oracle.json"))
        val exclusionsDocument = parseObject(fixture.path("function-oracle.json"))
        val exclusionFunctions = (exclusionsDocument.getValue("functions") as JsonArray).toMutableList()
        val excludedIndex = exclusionFunctions.indexOfFirst { (it as JsonObject).getValue("exclusion") != JsonNull }
        val excludedFunction = exclusionFunctions[excludedIndex] as JsonObject
        val exclusion = excludedFunction.getValue("exclusion") as JsonObject
        exclusionFunctions[excludedIndex] = JsonObject(
            excludedFunction + ("exclusion" to JsonObject(exclusion + ("reason" to JsonPrimitive("mutated reviewed exclusion")))),
        )
        writeCanonical(
            fixture.path("function-oracle.json"),
            JsonObject(exclusionsDocument + ("functions" to JsonArray(exclusionFunctions))),
        )
        val exclusionMutation = StructuralRecoveryV1Inputs.loadFunctionOracle(fixture.path("function-oracle.json"))
        assertFailsWith<StructuralRecoveryV1Exception> {
            StructuralRecoveryV1Inputs.loadBoundaryMapping(
                fixture.path("boundary-score.json"),
                "rich",
                target,
                exclusionMutation,
            )
        }
        Unit
    }

    @Test
    fun `identity and recovered provenance mutations fail after valid fixture reattestation`() = withStructuralFixture { fixture ->
        val target = StructuralRecoveryV1Inputs.loadTargetAbi(fixture.path("target-abi.json"))
        val functionOracle = StructuralRecoveryV1Inputs.loadFunctionOracle(fixture.path("function-oracle.json"))
        val oracle = StructuralRecoveryV1Inputs.loadStructuralOracle(fixture.path("structural-oracle.json"), target)
        val boundary = StructuralRecoveryV1Inputs.loadBoundaryMapping(
            fixture.path("boundary-score.json"),
            "rich",
            target,
            functionOracle,
        )

        val identity = parseObject(fixture.path("identity-map.json"))
        val mapHeader = identity.getValue("map") as JsonObject
        val staleMapHeader = JsonObject(mapHeader + ("oracleSha256" to JsonPrimitive("0".repeat(64))))
        writeCanonical(fixture.path("identity-map.json"), reattest(JsonObject(identity + ("map" to staleMapHeader))))
        assertFailsWith<StructuralRecoveryV1Exception> {
            StructuralRecoveryV1Inputs.loadFixtureIdentityMap(fixture.path("identity-map.json"), oracle)
        }

        copyResource("identity-map.json", fixture.path("identity-map.json"))
        val validIdentity = StructuralRecoveryV1Inputs.loadFixtureIdentityMap(fixture.path("identity-map.json"), oracle)
        val recovered = parseObject(fixture.path("recovered.json"))
        val provenance = recovered.getValue("provenance") as JsonObject
        val boundaryBinding = provenance.getValue("boundaryScore") as JsonObject
        val staleBoundary = JsonObject(boundaryBinding + ("sha256" to JsonPrimitive("f".repeat(64))))
        val staleProvenance = JsonObject(provenance + ("boundaryScore" to staleBoundary))
        writeCanonical(fixture.path("recovered.json"), reattest(JsonObject(recovered + ("provenance" to staleProvenance))))
        assertFailsWith<StructuralRecoveryV1Exception> {
            StructuralRecoveryV1Inputs.loadFixtureRecoveredStructure(
                fixture.path("recovered.json"),
                target,
                oracle,
                boundary,
                validIdentity,
            )
        }
        Unit
    }

    @Test
    fun `schema-valid report metric outcome and ordering forgeries are rejected`() = withStructuralFixture { fixture ->
        val target = StructuralRecoveryV1Inputs.loadTargetAbi(fixture.path("target-abi.json"))
        val report = parseObject(fixture.path("expected-score.json"))

        val aggregate = report.getValue("aggregate") as JsonObject
        val outcomes = aggregate.getValue("outcomes") as JsonObject
        val forgedOutcomes = JsonObject(outcomes + ("exact" to JsonPrimitive(15)))
        val forgedAggregate = JsonObject(aggregate + ("outcomes" to forgedOutcomes))
        assertFailsWith<StructuralRecoveryV1Exception> {
            StructuralRecoveryV1.validateFixtureReport(JsonObject(report + ("aggregate" to forgedAggregate)), target)
        }

        val entities = report.getValue("entities") as JsonArray
        assertFailsWith<StructuralRecoveryV1Exception> {
            StructuralRecoveryV1.validateFixtureReport(
                JsonObject(report + ("entities" to JsonArray(entities.reversed()))),
                target,
            )
        }

        val entity = entities[1] as JsonObject
        val facts = entity.getValue("facts") as JsonArray
        val fact = facts.first() as JsonObject
        val changedFact = JsonObject(fact + ("outcome" to JsonPrimitive("contradicted")))
        val changedEntity = JsonObject(entity + ("facts" to JsonArray(listOf(changedFact) + facts.drop(1))))
        val changedEntities = entities.toMutableList().apply { this[1] = changedEntity }
        assertFailsWith<StructuralRecoveryV1Exception> {
            StructuralRecoveryV1.validateFixtureReport(
                JsonObject(report + ("entities" to JsonArray(changedEntities))),
                target,
            )
        }
        Unit
    }

    @Test
    fun `production adapter replay claims remain outside the fixture API`() = withStructuralFixture { fixture ->
        val target = StructuralRecoveryV1Inputs.loadTargetAbi(fixture.path("target-abi.json"))
        val report = parseObject(fixture.path("expected-score.json"))
        val oracle = report.getValue("oracle") as JsonObject
        val model = report.getValue("model") as JsonObject
        val production = JsonObject(
            report + mapOf(
                "oracle" to JsonObject(oracle + ("scope" to JsonPrimitive("production"))),
                "model" to JsonObject(model + ("scope" to JsonPrimitive("production"))),
            ),
        )
        assertFailsWith<StructuralRecoveryV1Exception> {
            StructuralRecoveryV1.validateFixtureReport(production, target)
        }

        val identity = parseObject(fixture.path("identity-map.json"))
        writeCanonical(fixture.path("identity-map.json"), JsonObject(identity + ("scope" to JsonPrimitive("production"))))
        val oracleInput = StructuralRecoveryV1Inputs.loadStructuralOracle(fixture.path("structural-oracle.json"), target)
        assertFailsWith<StructuralRecoveryV1Exception> {
            StructuralRecoveryV1Inputs.loadFixtureIdentityMap(fixture.path("identity-map.json"), oracleInput)
        }
        Unit
    }

    @Test
    fun `hostile limits symlinks and group-writable inputs fail closed`() = withStructuralFixture { fixture ->
        assertFailsWith<StructuralRecoveryV1Exception> {
            fixture.load(StructuralRecoveryV1Limits(maximumMappings = 3))
        }
        assertFailsWith<StructuralRecoveryV1Exception> {
            fixture.load(
                StructuralRecoveryV1Limits(
                    maximumJsonInputBytes = Files.size(fixture.path("target-abi.json")).toInt() - 1,
                ),
            )
        }

        val link = fixture.path("target-link.json")
        Files.createSymbolicLink(link, fixture.path("target-abi.json").fileName)
        assertFailsWith<StructuralRecoveryV1Exception> { StructuralRecoveryV1Inputs.loadTargetAbi(link) }

        val targetPath = fixture.path("target-abi.json")
        if (Files.getFileStore(targetPath).supportsFileAttributeView("posix")) {
            Files.setPosixFilePermissions(targetPath, PosixFilePermissions.fromString("rw-rw----"))
            assertFailsWith<StructuralRecoveryV1Exception> { StructuralRecoveryV1Inputs.loadTargetAbi(targetPath) }
            Files.setPosixFilePermissions(targetPath, PosixFilePermissions.fromString("rw-------"))
        }

        val inputs = fixture.load()
        assertFailsWith<StructuralRecoveryV1Exception> {
            StructuralRecoveryV1.scoreFixture(
                inputs.oracle,
                inputs.recovered,
                inputs.boundary,
                inputs.identity,
                inputs.target,
                StructuralRecoveryV1Limits(maximumProjectedReportBytes = 1),
            )
        }
        assertFailsWith<StructuralRecoveryV1Exception> {
            StructuralRecoveryV1.scoreFixture(
                inputs.oracle,
                inputs.recovered,
                inputs.boundary,
                inputs.identity,
                inputs.target,
                StructuralRecoveryV1Limits(maximumReportBytes = 1_024),
            )
        }
        assertFalse(Files.exists(fixture.path("unexpected-report.json")))
    }

    @Test
    fun `atomic report publication leaves no partial output or owned temporary`() = withStructuralFixture { fixture ->
        val inputs = fixture.load()
        val report = StructuralRecoveryV1.scoreFixture(
            inputs.oracle,
            inputs.recovered,
            inputs.boundary,
            inputs.identity,
            inputs.target,
        )
        val bytes = StructuralRecoveryV1.canonicalReportBytes(report, inputs.target)
        val output = fixture.path("published-score.json")
        val binding = StructuralRecoveryV1.publishFixtureReport(output, report, inputs.target)
        assertTrue(bytes.contentEquals(Files.readAllBytes(output)))
        assertEquals(bytes.size, binding.sizeBytes)

        val failedOutput = fixture.path("failed-score.json")
        assertFailsWith<StructuralRecoveryV1Exception> {
            StructuralRecoveryV1Publication.publish(failedOutput, bytes, bytes.size) {
                throw IllegalStateException("deterministic failure before atomic move")
            }
        }
        assertFalse(Files.exists(failedOutput))
        val residue = Files.list(fixture.path(".")).use { paths ->
            paths.map { it.fileName.toString() }.filter { it.startsWith(".structural-v1-") }.toList()
        }
        assertEquals(emptyList(), residue)

        val symlinkOutput = fixture.path("symlink-score.json")
        Files.createSymbolicLink(symlinkOutput, fixture.path("target-abi.json").fileName)
        assertFailsWith<StructuralRecoveryV1Exception> {
            StructuralRecoveryV1.publishFixtureReport(symlinkOutput, report, inputs.target)
        }
        assertTrue(Files.isSymbolicLink(symlinkOutput))
    }
}

private val TEST_JSON_LIMITS = StrictJsonLimits(
    maximumInputBytes = 64 * 1024 * 1024,
    maximumCanonicalBytes = 64 * 1024 * 1024,
    maximumDepth = 128,
    maximumNodes = 1_000_000,
    maximumStringBytes = 1024 * 1024,
    maximumTotalStringBytes = 64 * 1024 * 1024,
    maximumNumberCharacters = 128,
)

private fun parseObject(path: java.nio.file.Path): JsonObject =
    OracleJson.parse(Files.readAllBytes(path), TEST_JSON_LIMITS) as JsonObject

private fun writeCanonical(path: java.nio.file.Path, document: JsonObject) {
    Files.write(path, OracleJson.canonicalBytes(document, TEST_JSON_LIMITS))
    setPermissions(path, "rw-------")
}

private fun reattest(document: JsonObject): JsonObject {
    val payloadSha256 = fixturePayloadSha256(document, 64 * 1024 * 1024)
    val attestation = document.getValue("attestation") as JsonObject
    return JsonObject(document + ("attestation" to JsonObject(attestation + ("payloadSha256" to JsonPrimitive(payloadSha256)))))
}

private fun copyResource(name: String, destination: java.nio.file.Path) {
    val bytes = checkNotNull(StructuralRecoveryV1MutationTest::class.java.getResourceAsStream("/oracle/structural-v1/$name"))
        .use { it.readAllBytes() }
    Files.write(destination, bytes)
    setPermissions(destination, "rw-------")
}
