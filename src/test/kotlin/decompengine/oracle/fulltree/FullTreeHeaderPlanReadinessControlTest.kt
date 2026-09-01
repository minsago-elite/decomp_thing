package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.lang.reflect.Modifier
import java.lang.reflect.Proxy
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.jupiter.api.Assumptions.assumeTrue

class FullTreeHeaderPlanReadinessControlTest {
    @Test
    fun `authenticated prerequisite envelope is deterministic incomplete and ACP first class`() =
        inControlTemporaryDirectory { directory ->
            val fixture = createReadinessFixture(directory.resolve("fixture"))
            val firstPath = directory.resolve("readiness-first.json")
            val secondPath = directory.resolve("readiness-second.json")

            val first = generateReadiness(fixture, firstPath)
            val second = generateReadiness(fixture, secondPath)

            assertContentEquals(first.canonicalBytes, second.canonicalBytes)
            assertContentEquals(Files.readAllBytes(firstPath), first.canonicalBytes)
            assertEquals(first.artifactSha256, second.artifactSha256)
            assertEquals(first.reportSha256, second.reportSha256)
            assertEquals(2, first.sourceModules.size)
            assertEquals(3, first.sourceOnlyUnits.size)
            assertTrue(first.authenticatedSourceHeaderCandidatePaths.isEmpty())
            assertEquals(EXPECTED_BLOCKERS, first.blockerCodes)
            assertEquals(fixtureSha256(fixture.planning), first.planningInventoryArtifactSha256)
            assertEquals(fixtureSha256(fixture.control.sourceArchive), first.sourceArchiveSha256)

            val document = parseControlObject(firstPath)
            assertEquals("full-tree-header-plan-readiness-v1", document.controlString("kind"))
            val authority = document.controlObject("authority")
            assertEquals("incomplete-authenticated-prerequisites", authority.controlString("status"))
            listOf(
                "cleanCompilationProven",
                "compilerCaptureAuthenticated",
                "headerPlanReady",
                "headerPopulationComplete",
                "releaseEligible",
            ).forEach { field -> assertFalse(authority.getValue(field).toString().toBoolean()) }
            val acp = document.controlObject("acpBoundary")
            assertEquals("first-class-candidate-producer-operator", acp.controlString("role"))
            assertEquals("not-an-input-to-readiness-v1", acp.controlString("candidateLineageAdmission"))
            assertEquals(
                "non-authoritative-input-to-later-host-validation",
                acp.controlString("candidateEvidenceDisposition"),
            )
            listOf(
                "oracleAuthority",
                "referenceAuthoringAuthority",
                "policyAuthoringAuthority",
                "validationAuthority",
                "observationAuthoringAuthority",
                "startAuthority",
                "containmentAuthority",
                "terminalAbsenceAuthority",
                "scoringAuthority",
                "certificationAuthority",
                "releaseAuthority",
            ).forEach { field -> assertFalse(acp.getValue(field).toString().toBoolean()) }
            assertEquals(
                JsonObject(
                    mapOf(
                        "authenticatedSourceHeaderCandidates" to JsonPrimitive(0),
                        "blockers" to JsonPrimitive(5),
                        "generatedSourceModules" to JsonPrimitive(1),
                        "handwrittenSourceModules" to JsonPrimitive(1),
                        "outputRecords" to JsonPrimitive(10),
                        "sourceModules" to JsonPrimitive(2),
                        "sourceOnlyUnits" to JsonPrimitive(3),
                        "workUnits" to JsonPrimitive(34),
                    ),
                ),
                document.controlObject("counts"),
            )
            assertEquals(
                EXPECTED_BLOCKERS,
                document.controlArray("blockers").controlObjects("readiness blockers")
                    .map { it.controlString("code") },
            )

            val loaded = loadReadiness(fixture, firstPath)
            assertEquals(first.artifactSha256, loaded.artifactSha256)
            assertContentEquals(first.canonicalBytes, loaded.canonicalBytes)
        }

    @Test
    fun `authenticated source header candidates are positive serialized and bounded by manifest`(): Unit =
        inControlTemporaryDirectory { directory ->
            val dependencyFixture = createDependencyFixtureWithSourceHeaders(
                directory.resolve("positive"),
                listOf("fixture.h", "second.inc"),
            )
            val fixture = ReadinessFixture(dependencyFixture.control, dependencyFixture.planning)
            val output = directory.resolve("readiness-positive.json")

            val readiness = generateReadiness(fixture, output)

            val expectedPaths = listOf(
                "source/clang/include/fixture.h",
                "source/clang/include/second.inc",
            )
            assertEquals(expectedPaths, readiness.authenticatedSourceHeaderCandidatePaths)
            assertEquals(
                "13b1eef5e10a238dcdb2a0f439d9351ce6fe2acbbd5ea96a57e7f010f6753fbf",
                readiness.sourceHeaderManifestSha256,
            )
            val document = parseControlObject(output)
            assertEquals(
                expectedPaths,
                document.controlObject("populations")
                    .controlArray("authenticatedSourceHeaderCandidates")
                    .map { it.controlString("authenticated source-header candidate") },
            )
            assertEquals(2L, document.controlObject("counts").controlLong("authenticatedSourceHeaderCandidates"))
            assertEquals(12L, document.controlObject("counts").controlLong("outputRecords"))
            assertEquals(40L, document.controlObject("counts").controlLong("workUnits"))
            assertFailsWith<FullTreeHeaderPlanReadinessException> {
                generateReadiness(
                    fixture,
                    directory.resolve("readiness-bounded.json"),
                    FullTreeHeaderPlanReadinessLimits(maximumAuthenticatedSourceHeaderCandidates = 1),
                )
            }
        }

    @Test
    fun `readiness result is deeply immutable and has no caller-authored population seam`() =
        inControlTemporaryDirectory { directory ->
            val fixture = createReadinessFixture(directory.resolve("immutable"))
            val readiness = generateReadiness(fixture, directory.resolve("readiness.json"))

            @Suppress("UNCHECKED_CAST")
            assertFailsWith<UnsupportedOperationException> {
                (readiness.sourceModules as MutableList<FullTreePlanningSourceModule>).clear()
            }
            @Suppress("UNCHECKED_CAST")
            assertFailsWith<UnsupportedOperationException> {
                (readiness.sourceOnlyUnits as MutableList<FullTreePlanningSourceOnlyUnit>).clear()
            }
            @Suppress("UNCHECKED_CAST")
            assertFailsWith<UnsupportedOperationException> {
                (readiness.authenticatedSourceHeaderCandidatePaths as MutableList<String>) +=
                    "source/forged.h"
            }
            @Suppress("UNCHECKED_CAST")
            assertFailsWith<UnsupportedOperationException> {
                (readiness.blockerCodes as MutableList<String>).clear()
            }
            val firstBytes = readiness.canonicalBytes
            firstBytes[0] = 'x'.code.toByte()
            assertFalse(firstBytes.contentEquals(readiness.canonicalBytes))

            val implementation = Class.forName(
                "decompengine.oracle.fulltree.FullTreeHeaderPlanReadinessControl\$ValidatedReadiness",
            )
            implementation.declaredConstructors.forEach { constructor ->
                assertTrue(constructor.parameterTypes.all { type ->
                    type == Path::class.java ||
                        type == FullTreeHeaderPlanReadinessLimits::class.java ||
                        type == Boolean::class.javaPrimitiveType ||
                        type.name == "kotlin.jvm.internal.DefaultConstructorMarker"
                })
                assertFalse(constructor.parameterTypes.any { type ->
                    type == ByteArray::class.java ||
                        JsonObject::class.java.isAssignableFrom(type) ||
                        Collection::class.java.isAssignableFrom(type) ||
                        AuthenticatedFullTreePlanningRegistry::class.java.isAssignableFrom(type)
                })
            }
            assertFailsWith<IllegalArgumentException> {
                Proxy.newProxyInstance(
                    AuthenticatedFullTreeHeaderPlanReadiness::class.java.classLoader,
                    arrayOf(AuthenticatedFullTreeHeaderPlanReadiness::class.java),
                ) { _, _, _ -> null }
            }
            FullTreeHeaderPlanReadinessControl::class.java.declaredMethods
                .filter { Modifier.isPublic(it.modifiers) && it.name in setOf("generateAndPublish", "loadAndValidate") }
                .forEach { method ->
                    assertTrue(method.parameterTypes.all { type ->
                        type == Path::class.java || type == FullTreeHeaderPlanReadinessLimits::class.java
                    })
                }
        }

    @Test
    fun `semantic tampering and every populated lowering bound fail closed`(): Unit =
        inControlTemporaryDirectory { directory ->
            val fixture = createReadinessFixture(directory.resolve("fail-closed"))
            val output = directory.resolve("readiness.json")
            generateReadiness(fixture, output)

            val valid = parseControlObject(output)
            val forgedOracle = JsonObject(
                valid.controlObject("oracle") +
                    ("sourceHeaderManifestSha256" to JsonPrimitive("f".repeat(64))),
            )
            writeControlObject(output, rehashReadiness(JsonObject(valid + ("oracle" to forgedOracle))))
            assertFailsWith<FullTreeHeaderPlanReadinessException> { loadReadiness(fixture, output) }

            generateReadiness(fixture, output)
            val forgedAcp = JsonObject(
                parseControlObject(output).controlObject("acpBoundary") +
                    ("oracleAuthority" to JsonPrimitive(true)),
            )
            val withAuthority = parseControlObject(output)
            writeControlObject(
                output,
                rehashReadiness(JsonObject(withAuthority + ("acpBoundary" to forgedAcp))),
            )
            assertFailsWith<FullTreeHeaderPlanReadinessException> { loadReadiness(fixture, output) }

            listOf(
                FullTreeHeaderPlanReadinessLimits(maximumSourceModules = 1),
                FullTreeHeaderPlanReadinessLimits(maximumSourceOnlyUnits = 2),
                FullTreeHeaderPlanReadinessLimits(maximumBlockers = 4),
                FullTreeHeaderPlanReadinessLimits(maximumOutputRecords = 9),
                FullTreeHeaderPlanReadinessLimits(maximumWorkUnits = 33),
                FullTreeHeaderPlanReadinessLimits(maximumSerializedBytes = 1),
            ).forEach { limits ->
                assertFailsWith<FullTreeHeaderPlanReadinessException> {
                    generateReadiness(fixture, output, limits)
                }
            }
            assertFailsWith<FullTreeHeaderPlanReadinessException> {
                generateReadiness(fixture, fixture.planning)
            }
        }

    @Test
    fun `locked LLVM archive reproduces readiness populations and source manifest`() =
        inControlTemporaryDirectory { directory ->
            val archive = System.getenv("DECOMP_LLVM_SOURCE_ARCHIVE")
                ?.takeIf(String::isNotBlank)?.let(Path::of)
            assumeTrue(archive != null && Files.isRegularFile(archive), "set DECOMP_LLVM_SOURCE_ARCHIVE")
            val profile = Path.of("oracle/llvm/22.1.6").toAbsolutePath().normalize()
            val readiness = FullTreeHeaderPlanReadinessControl.generateAndPublish(
                sourceArchivePath = requireNotNull(archive),
                scopePath = profile.resolve("full-tree-scope.json"),
                sourceLockPath = profile.resolve("source-lock.json"),
                artifactManifestPath = profile.resolve("oracle-manifest.json"),
                buildRecordPath = profile.resolve("build-record.json"),
                inventoryPath = profile.resolve("full-tree-inventory.json"),
                sourceInventoryPath = profile.resolve("full-tree-source-inventory.json"),
                planningInventoryPath = profile.resolve("full-tree-planning-inventory.json"),
                output = directory.resolve("full-tree-header-plan-readiness.json"),
            )

            assertEquals(2_150, readiness.sourceModules.size)
            assertEquals(2_325, readiness.sourceOnlyUnits.size)
            assertEquals(6_579, readiness.authenticatedSourceHeaderCandidatePaths.size)
            assertEquals(
                "a508d401c9904e2a18b52bb6f1e77cf06d0944e5ced8888c4c010f196e2310fc",
                readiness.sourceHeaderManifestSha256,
            )
            assertEquals(EXPECTED_BLOCKERS, readiness.blockerCodes)
            assertEquals(FROZEN_CONFIGURATION_SHA256, FullTreeHeaderPlanReadinessControl.configurationSha256)
            assertEquals(FROZEN_CONFIGURATION_SHA256, readiness.configurationSha256)
            assertEquals(FROZEN_REPORT_SHA256, readiness.reportSha256)
            assertEquals(FROZEN_ARTIFACT_SHA256, readiness.artifactSha256)
            assertEquals(FROZEN_ARTIFACT_BYTES, readiness.artifactBytes)
            val counts = parseControlObject(directory.resolve("full-tree-header-plan-readiness.json"))
                .controlObject("counts")
            assertEquals(11_059L, counts.controlLong("outputRecords"))
            assertEquals(33_181L, counts.controlLong("workUnits"))
        }

    private fun generateReadiness(
        fixture: ReadinessFixture,
        output: Path,
        limits: FullTreeHeaderPlanReadinessLimits = FullTreeHeaderPlanReadinessLimits(),
    ): AuthenticatedFullTreeHeaderPlanReadiness = FullTreeHeaderPlanReadinessControl.generateAndPublish(
        fixture.control.sourceArchive,
        fixture.control.scope,
        fixture.control.sourceLock,
        fixture.control.manifest,
        fixture.control.buildRecord,
        fixture.control.inventory,
        fixture.control.sourceInventory,
        fixture.planning,
        output,
        limits,
    )

    private fun loadReadiness(
        fixture: ReadinessFixture,
        path: Path,
    ): AuthenticatedFullTreeHeaderPlanReadiness = FullTreeHeaderPlanReadinessControl.loadAndValidate(
        path,
        fixture.control.sourceArchive,
        fixture.control.scope,
        fixture.control.sourceLock,
        fixture.control.manifest,
        fixture.control.buildRecord,
        fixture.control.inventory,
        fixture.control.sourceInventory,
        fixture.planning,
    )

    private companion object {
        val EXPECTED_BLOCKERS = listOf(
            "complete-project-header-inventory-missing",
            "compiler-capture-provenance-missing",
            "generated-file-provenance-missing",
            "ninja-generator-provenance-missing",
            "physical-project-roots-unverified",
        )
        const val FROZEN_CONFIGURATION_SHA256 =
            "ebcb5f0a6f1254a6d6e0c8627acb6a493745a3babb66f354f228eba9e48b2894"
        const val FROZEN_REPORT_SHA256 =
            "2020c2feec9ce0333d10d9e0948fd56b532872ec8f4a16a5f5226952874f30f5"
        const val FROZEN_ARTIFACT_SHA256 =
            "ad3f97793f48b034f56d05481b9bf9b4ca940bcba67e11ebdfbf07b149be549b"
        const val FROZEN_ARTIFACT_BYTES = 1_486_296L
    }
}

private data class ReadinessFixture(
    val control: FullTreeControlFixture,
    val planning: Path,
)

private fun createReadinessFixture(root: Path): ReadinessFixture {
    Files.createDirectories(root)
    Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
    val control = createFullTreeControlFixture(root.resolve("control"))
    val planning = root.resolve("planning.json")
    FullTreePlanningInventoryControl.generateAndPublish(
        control.scope,
        control.sourceLock,
        control.manifest,
        control.buildRecord,
        control.inventory,
        control.sourceInventory,
        planning,
    )
    return ReadinessFixture(control, planning)
}

private fun rehashReadiness(document: JsonObject): JsonObject {
    val withoutHash = JsonObject(document.filterKeys { it != "reportSha256" })
    val reportSha256 = OracleArtifacts.sha256(
        OracleJson.canonicalBytes(withoutHash, controlJsonLimits(HEADER_READINESS_MAXIMUM_SERIALIZED_BYTES)),
    )
    return JsonObject(withoutHash + ("reportSha256" to JsonPrimitive(reportSha256)))
}
