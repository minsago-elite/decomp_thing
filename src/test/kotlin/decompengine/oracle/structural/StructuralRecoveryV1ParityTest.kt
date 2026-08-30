package decompengine.oracle.structural

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonObject

class StructuralRecoveryV1ParityTest {
    @Test
    fun `JVM scorer is byte-identical to the frozen historical v1 report`() = withStructuralFixture { fixture ->
        val inputs = fixture.load()
        val first = StructuralRecoveryV1.scoreFixture(
            inputs.oracle,
            inputs.recovered,
            inputs.boundary,
            inputs.identity,
            inputs.target,
        )
        val second = StructuralRecoveryV1.scoreFixture(
            inputs.oracle,
            inputs.recovered,
            inputs.boundary,
            inputs.identity,
            inputs.target,
        )
        val firstBytes = StructuralRecoveryV1.canonicalReportBytes(first, inputs.target)
        val secondBytes = StructuralRecoveryV1.canonicalReportBytes(second, inputs.target)
        val frozenBytes = Files.readAllBytes(fixture.path("expected-score.json"))

        assertTrue(firstBytes.contentEquals(frozenBytes))
        assertTrue(secondBytes.contentEquals(frozenBytes))
        assertEquals(EXPECTED_REPORT_SHA256, OracleArtifacts.sha256(firstBytes))
        assertEquals(20, (first.getValue("dimensions") as kotlinx.serialization.json.JsonArray).size)
        val aggregate = first.getValue("aggregate") as JsonObject
        assertEquals(24, aggregate.requiredInt("oracleDenominator"))
        assertEquals(26, aggregate.requiredInt("recoveredDenominator"))
        val outcomes = aggregate.getValue("outcomes") as JsonObject
        assertEquals(14, outcomes.requiredInt("exact"))
        assertEquals(4, outcomes.requiredInt("abi-equivalent"))
        assertEquals(3, outcomes.requiredInt("recovered-unknown"))
        assertEquals(1, outcomes.requiredInt("oracle-unobservable"))
        assertEquals(2, outcomes.requiredInt("contradicted"))
        assertEquals(3, outcomes.requiredInt("fabricated"))
    }

    @Test
    fun `frozen report independently validates and all fixture digests remain pinned`() = withStructuralFixture { fixture ->
        val inputs = fixture.load()
        val report = OracleJson.parse(
            Files.readAllBytes(fixture.path("expected-score.json")),
            StrictJsonLimits(
                maximumInputBytes = 64 * 1024 * 1024,
                maximumCanonicalBytes = 64 * 1024 * 1024,
                maximumDepth = 128,
                maximumNodes = 1_000_000,
                maximumStringBytes = 1024 * 1024,
                maximumTotalStringBytes = 64 * 1024 * 1024,
                maximumNumberCharacters = 128,
            ),
        ) as JsonObject
        StructuralRecoveryV1.validateFixtureReport(report, inputs.target)
        assertTrue(
            StructuralRecoveryV1.canonicalReportBytes(report, inputs.target)
                .contentEquals(Files.readAllBytes(fixture.path("expected-score.json"))),
        )
        FROZEN_DIGESTS.forEach { (name, expected) ->
            assertEquals(expected, OracleArtifacts.sha256(Files.readAllBytes(fixture.path(name))), name)
        }
    }

    @Test
    fun `canonical comparisons use Unicode code points rather than UTF-16 units`() {
        val privateUse = "\ue000"
        val supplementary = "\ud800\udc00"
        assertTrue(privateUse > supplementary, "the JVM's UTF-16 order must differ for this regression pair")
        assertTrue(compareCodePoints(privateUse, supplementary) < 0)
        assertTrue(compareCodePoints(supplementary, privateUse) > 0)
    }

    private fun JsonObject.requiredInt(name: String): Int =
        (getValue(name) as kotlinx.serialization.json.JsonPrimitive).content.toInt()

    private companion object {
        const val EXPECTED_REPORT_SHA256 = "2dbff117253ba927a84df1e428f62d97b1f0efde049d4e6b78dc050dc5456ce6"
        val FROZEN_DIGESTS = mapOf(
            "target-abi.json" to "d251d5e6a0edc17655c355fb8fd757d557f064a6e67095ad53c8ca1e7569a343",
            "function-oracle.json" to "3239d0747456fb92edb48c322464cd76573236b107454d84b10553da23299f93",
            "boundary-score.json" to "b05d85d9f21e704c2581b84ded3ea5442eb4695ed75e74d25778e417a5a8d593",
            "structural-oracle.json" to "9a479186e5d0595a0820e399e2d789f2a108497f0089f4b64e8247e3fbfa129d",
            "identity-map.json" to "836f2f29dc233c29a9da8356c7f4f8d51d0d7c80ce8c338963568f2b7ec93ae9",
            "recovered.json" to "ea0cbf88f2212a271e966e348be00ac943aa0c375ffe631d32fdf44b87996a65",
            "expected-score.json" to EXPECTED_REPORT_SHA256,
        )
    }
}

internal data class LoadedStructuralV1Fixture(
    val target: StructuralTargetAbiV1,
    val functionOracle: StructuralFunctionOracleV1,
    val oracle: StructuralOracleV1,
    val boundary: StructuralBoundaryMappingV1,
    val identity: StructuralIdentityMapV1,
    val recovered: RecoveredStructureV1,
)

internal class StructuralV1Fixture(private val root: Path) {
    fun path(name: String): Path = root.resolve(name)

    fun load(limits: StructuralRecoveryV1Limits = StructuralRecoveryV1Limits()): LoadedStructuralV1Fixture {
        val target = StructuralRecoveryV1Inputs.loadTargetAbi(path("target-abi.json"), limits)
        val functionOracle = StructuralRecoveryV1Inputs.loadFunctionOracle(path("function-oracle.json"), limits)
        val oracle = StructuralRecoveryV1Inputs.loadStructuralOracle(path("structural-oracle.json"), target, limits)
        val boundary = StructuralRecoveryV1Inputs.loadBoundaryMapping(
            path("boundary-score.json"),
            "rich",
            target,
            functionOracle,
            limits,
        )
        val identity = StructuralRecoveryV1Inputs.loadFixtureIdentityMap(path("identity-map.json"), oracle, limits)
        val recovered = StructuralRecoveryV1Inputs.loadFixtureRecoveredStructure(
            path("recovered.json"),
            target,
            oracle,
            boundary,
            identity,
            limits,
        )
        return LoadedStructuralV1Fixture(target, functionOracle, oracle, boundary, identity, recovered)
    }
}

internal fun <T> withStructuralFixture(block: (StructuralV1Fixture) -> T): T {
    val directory = createTempDirectory("structural-v1-")
    return try {
        setPermissions(directory, "rwx------")
        STRUCTURAL_RESOURCE_NAMES.forEach { name ->
            val bytes = checkNotNull(StructuralRecoveryV1ParityTest::class.java.getResourceAsStream("/oracle/structural-v1/$name")) {
                "missing structural v1 resource: $name"
            }.use { it.readAllBytes() }
            val destination = directory.resolve(name)
            Files.write(destination, bytes)
            setPermissions(destination, "rw-------")
        }
        block(StructuralV1Fixture(directory))
    } finally {
        Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
    }
}

internal fun setPermissions(path: Path, mode: String) {
    try {
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString(mode))
    } catch (_: UnsupportedOperationException) {
        // OracleArtifacts applies the available platform checks on non-POSIX hosts.
    }
}

private val STRUCTURAL_RESOURCE_NAMES = listOf(
    "target-abi.json",
    "function-oracle.json",
    "boundary-score.json",
    "structural-oracle.json",
    "identity-map.json",
    "recovered.json",
    "expected-score.json",
    "provenance.json",
)
