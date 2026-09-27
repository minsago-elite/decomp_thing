package decompengine.project

import decompengine.agent.AgentCancellation
import decompengine.repair.RepairCandidateValidationRequest
import decompengine.repair.RepairResourceBudget
import decompengine.repair.repairCandidateSourceSha256
import decompengine.repair.repairRegressionCorpusSha256
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue

/** Opt-in quota-backed fixture; no contained compiler or production validation authority is created. */
class GeneratedCValidationSnapshotFixtureTest {
    @Test
    fun `Make Ninja and relocated inputs populate only declared quota backed source snapshots`() {
        val sourceMount = System.getenv("DECOMP_TEST_REPAIR_SOURCE_TMPFS")?.let(Path::of)
        val outputMount = System.getenv("DECOMP_TEST_REPAIR_OUTPUT_TMPFS")?.let(Path::of)
        assumeTrue(sourceMount != null && outputMount != null, "dedicated repair tmpfs mounts are not configured")
        val source = requireNotNull(sourceMount)
        val output = requireNotNull(outputMount)
        val budget = RepairResourceBudget()

        fun request(registration: GeneratedCValidationRegistration, sources: Map<String, ByteArray>) =
            RepairCandidateValidationRequest(
                projectDir = Path.of(".").toAbsolutePath().normalize(),
                candidateSources = sources,
                sourceRevisionSha256 = repairCandidateSourceSha256(sources),
                profileId = registration.indexProfile.profileId(),
                profileSha256 = registration.indexProfile.configurationSha256(budget),
                indexSha256 = "a".repeat(64),
                originalBinary = null,
                inputs = emptyList(),
                regressionCorpusSha256 = repairRegressionCorpusSha256(emptyList()),
                reportsDir = Path.of(".").toAbsolutePath().normalize(),
                label = "authored-snapshot",
                budget = budget,
                deadlineNanos = Long.MAX_VALUE,
                cancellation = AgentCancellation.NONE,
            )

        val make = GeneratedCValidationProfile.registeredMake
        val ninja = GeneratedCValidationRegistration(GeneratedCNinjaReconstructionProfile.descriptor)
        val base = GeneratedCMakeReconstructionProfile.descriptor
        val relocatedProfile = ReconstructionProfile(base.schemaVersion, base.id,
            ProjectLayoutProfile(base.layout.schemaVersion, base.layout.declarations.map { declaration ->
                val path = when (declaration.id) {
                    "build-definition" -> "config/build/Makefile"
                    else -> declaration.pathTemplate
                        .replace(Regex("^src/"), "workspace/code/")
                        .replace(Regex("^include/"), "workspace/headers/")
                }
                ProjectFileDeclaration(declaration.id, path, declaration.roles, declaration.contentKind)
            }), base.budgets, base.adapterConfiguration)
        val relocated = GeneratedCValidationRegistration(relocatedProfile)
        val cases = listOf(
            make to mapOf("Makefile" to "all:\n\t@true\n".toByteArray(),
                "include/decomp_types.h" to "/* header */\n".toByteArray(),
                "src/main.c" to "int main(void) { return 0; }\n".toByteArray(),
                "src/auxiliary.c" to "/* undeclared read-only input */\n".toByteArray()),
            ninja to mapOf("build.ninja" to "build all: phony\n".toByteArray(),
                "include/decomp_types.h" to "/* header */\n".toByteArray(),
                "src/main.c" to "int main(void) { return 0; }\n".toByteArray(),
                "src/auxiliary.c" to "/* undeclared read-only input */\n".toByteArray()),
            relocated to mapOf("config/build/Makefile" to "all:\n\t@true\n".toByteArray(),
                "workspace/headers/decomp_types.h" to "/* header */\n".toByteArray(),
                "workspace/code/main.c" to "int main(void) { return 0; }\n".toByteArray(),
                "workspace/code/auxiliary.c" to "/* undeclared read-only input */\n".toByteArray()),
        )
        cases.forEach { (registration, sources) ->
            GeneratedCValidationSnapshot.createForSourceFixture(source, output, registration, budget).use { snapshot ->
                if (registration !== make) {
                    assertFailsWith<IllegalArgumentException> { snapshot.populate(request(make, sources)) }
                    Files.newDirectoryStream(snapshot.source.path).use { assertFalse(it.iterator().hasNext()) }
                }
                val outside = sources + mapOf("foreign/undeclared.c" to "int x;\n".toByteArray())
                assertFailsWith<IllegalArgumentException> { snapshot.populate(request(registration, outside)) }
                Files.newDirectoryStream(snapshot.source.path).use { assertFalse(it.iterator().hasNext()) }
                snapshot.populate(request(registration, sources))
                assertNotNull(snapshot.sourceManifestSha256)
                assertEquals(sources.keys.sorted(), snapshot.sourceFiles.map { it.getValue("path").toString().trim('"') })
                val buildDefinition = registration.sources.buildDefinition
                assertEquals("\"build-file\"", snapshot.sourceFiles.single {
                    it.getValue("path").toString() == "\"$buildDefinition\""
                }.getValue("role").toString())
                val auxiliary = sources.keys.single { it.endsWith("/auxiliary.c") }
                assertFalse(registration.sources.isEditable(auxiliary))
                sources.forEach { (relative, bytes) ->
                    val staged = snapshot.source.path.resolve(relative)
                    assertTrue(Files.isRegularFile(staged))
                    assertTrue(Files.readAllBytes(staged).contentEquals(bytes))
                    assertEquals(PosixFilePermissions.fromString("r--r--r--"), Files.getPosixFilePermissions(staged))
                }
                snapshot.newOutput()
                snapshot.finishOutput()
            }
            Files.newDirectoryStream(source).use { assertFalse(it.iterator().hasNext()) }
            Files.newDirectoryStream(output).use { assertFalse(it.iterator().hasNext()) }
        }
    }
}
