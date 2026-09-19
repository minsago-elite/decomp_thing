package decompengine.validation

import decompengine.project.GeneratedCMakeReconstructionProfile
import decompengine.project.GeneratedCNinjaReconstructionProfile
import decompengine.project.ProjectFileDeclaration
import decompengine.project.ProjectFileRole
import decompengine.project.ProjectLayoutProfile
import decompengine.project.ReconstructionAdapters
import decompengine.project.ReconstructionProfile
import decompengine.project.RecoveredCModuleReconstructor
import decompengine.project.RecoveredFunction
import decompengine.project.RecoveredProgramModel
import decompengine.project.SourceTreeGenerator
import java.nio.file.Path
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class ProfiledBehaviorEvidenceCaptureTest {
    @Test
    fun `Make and Ninja behavior capture retain the exact built source revision`() {
        for (profile in profiles()) {
            val fixture = fixture(profile)
            val (capture, evidence) = capture(fixture)

            assertBuildIdentity(fixture, evidence)
            assertEquals(profile.id, evidence.getValue("profileId").jsonPrimitive.content)
            assertEquals(profile.sha256, evidence.getValue("profileSha256").jsonPrimitive.content)
            if (profile.id == GeneratedCNinjaReconstructionProfile.PROFILE_ID) {
                assertFalse(fixture.project.resolve("Makefile").exists())
                assertTrue("build.ninja" in evidence.inputPaths())
            }
            capture.requireCurrent()
        }
    }

    @Test
    fun `relocated build definitions and module inputs are captured exactly once`() {
        for (base in profiles()) {
            val fileName = if (base.id == GeneratedCNinjaReconstructionProfile.PROFILE_ID) "build.ninja" else "rebuild.mk"
            for (buildDefinition in listOf("config/$fileName", "src/config/$fileName")) {
                val profile = relocatedProfile(base, buildDefinition)
                val fixture = fixture(profile)
                val (capture, evidence) = capture(fixture)
                val paths = evidence.inputPaths()

                assertBuildIdentity(fixture, evidence)
                assertEquals(profile.sha256, evidence.getValue("profileSha256").jsonPrimitive.content)
                assertEquals(1, paths.count { it == buildDefinition }, buildDefinition)
                assertTrue(fixture.moduleSource.startsWith("src/units/"))
                assertTrue(fixture.moduleSource in paths)
                assertTrue(paths.any { it.startsWith("src/units/") && it.endsWith("_internal.h") })
                assertFalse(fixture.project.resolve(base.layout.declaration("build-definition").materialize()).exists())
                capture.requireCurrent()
            }
        }
    }

    @Test
    fun `profiled behavior capture notices a later source comment edit`() {
        for (profile in profiles()) {
            val fixture = fixture(profile)
            val (capture, evidence) = capture(fixture)
            assertBuildIdentity(fixture, evidence)
            capture.requireCurrent()

            val source = fixture.project.resolve(fixture.moduleSource)
            source.writeText(source.readText() + "\n/* authored edit after capture */\n")

            val failure = assertFailsWith<IllegalArgumentException>(profile.id) { capture.requireCurrent() }
            assertTrue(failure.message.orEmpty().contains("behavior evidence input changed during execution"))
        }
    }

    private fun profiles() = listOf(
        GeneratedCMakeReconstructionProfile.descriptor,
        GeneratedCNinjaReconstructionProfile.descriptor,
    )

    private fun relocatedProfile(base: ReconstructionProfile, buildDefinition: String): ReconstructionProfile {
        val paths = mapOf(
            "build-definition" to buildDefinition,
            "module-implementation" to "src/units/{module}.c",
            "module-private-interface" to "src/units/{module}_internal.h",
        )
        val layout = ProjectLayoutProfile(base.layout.schemaVersion, base.layout.declarations.map { declaration ->
            ProjectFileDeclaration(declaration.id, paths[declaration.id] ?: declaration.pathTemplate,
                declaration.roles, declaration.contentKind)
        })
        return ReconstructionProfile(base.schemaVersion, base.id, layout, base.budgets, base.adapterConfiguration)
    }

    private data class Fixture(
        val project: Path,
        val profile: ReconstructionProfile,
        val inputSha256: String,
        val expectedInputs: List<String>,
        val moduleSource: String,
        val buildContract: JsonObject,
    )

    private fun fixture(profile: ReconstructionProfile): Fixture {
        val project = createTempDirectory("profiled-behavior-capture-")
        val model = RecoveredProgramModel(
            inputSha256 = "a".repeat(64),
            functions = listOf(RecoveredFunction(
                "fn_1000", "decomp_engine_main", 0x1000UL, "int decomp_engine_main(void)",
                "int decomp_engine_main(void) { return 7; }",
            )),
        )
        val manifest = SourceTreeGenerator.generate(model, project,
            reconstructor = RecoveredCModuleReconstructor(), profile = profile)
        assertEquals(0, ReconstructionAdapters.resolve(profile).build(project, profile).returnCode)
        val inputs = manifest.files.filter { ProjectFileRole.BUILD_INPUT in it.roles }.map { it.path }.sorted()
        val moduleSource = manifest.files.single { ProjectFileRole.MODULE_IMPLEMENTATION in it.roles }.path
        val contract = Json.parseToJsonElement(project.resolve("reports/build_contract.json").readText()).jsonObject
        return Fixture(project, profile, model.inputSha256, inputs, moduleSource, contract)
    }

    private fun capture(fixture: Fixture): Pair<BehaviorEvidenceCapture, JsonObject> {
        val capture = BehaviorEvidenceCapture()
        val evidence = capture.project(
            BehaviorProjectContext(fixture.project, fixture.profile),
            JsonObject(mapOf("sha256" to JsonPrimitive(fixture.inputSha256))),
            fixture.project.resolve("build/reconstructed"),
        )
        return capture to evidence
    }

    private fun assertBuildIdentity(fixture: Fixture, evidence: JsonObject) {
        assertEquals(fixture.inputSha256, evidence.getValue("inputSha256").jsonPrimitive.content)
        assertEquals(fixture.buildContract.getValue("sourceInputs"), evidence.getValue("sourceInputs"))
        assertEquals(fixture.buildContract.getValue("sourceRevisionSha256"), evidence.getValue("sourceRevisionSha256"))
        assertEquals(fixture.buildContract.getValue("artifact"), evidence.getValue("artifact"))
        assertEquals(fixture.expectedInputs, evidence.inputPaths())
    }

    private fun JsonObject.inputPaths(): List<String> = getValue("sourceInputs").jsonArray.map {
        it.jsonObject.getValue("path").jsonPrimitive.content
    }
}
