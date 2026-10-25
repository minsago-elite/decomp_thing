package decompengine.project

import decompengine.agent.AgentHarness
import decompengine.validation.SandboxUnavailableException
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import org.junit.jupiter.api.Assumptions.assumeTrue

class ModuleCompilationAvailabilityTest {
    @Test
    fun `missing contained runtime prevents agent dispatch and current acceptance`() = withoutRuntime { project ->
        var dispatches = 0
        val reconstructor = BoundedLlmModuleReconstructor(AgentHarness { _, _ ->
            dispatches++
            error("runtime preflight must precede dispatch")
        })
        val failure = assertFailsWith<SandboxUnavailableException> {
            SourceTreeGenerator.generate(model(), project, reconstructor = reconstructor)
        }
        assertTrue(failure.message.orEmpty().contains(ContainedModuleCompilationRuntimeConfiguration.ENVIRONMENT))
        assertEquals(0, dispatches)
        assertFalse(Files.exists(project.resolve("reports/modules/alpha.json")))
    }

    @Test
    fun `evidence only unresolved output requires no contained runtime or compiler claim`() = withoutRuntime { project ->
        val manifest = SourceTreeGenerator.generate(model(), project, reconstructor = EvidenceModuleReconstructor())
        assertTrue(manifest.unresolvedImplementationIds.isNotEmpty())
        val source = manifest.files.single { ProjectFileRole.MODULE_IMPLEMENTATION in it.roles }
        assertEquals(false, source.acceptedImplementation)
        val moduleId = GeneratedCMakeReconstructionProfile.descriptor.layout.declaration("module-implementation")
            .moduleIdForPath(source.path)
        val checkpoint = Json.parseToJsonElement(Files.readString(project.resolve("reports/modules/$moduleId.json"))).jsonObject
        assertEquals(JsonPrimitive(7), checkpoint.getValue("schemaVersion"))
        assertEquals(JsonNull, checkpoint.getValue("compilation"))
    }

    private fun withoutRuntime(action: (Path) -> Unit) {
        assumeTrue(System.getenv(ContainedModuleCompilationRuntimeConfiguration.ENVIRONMENT) == null &&
            System.getenv("GENERATED_C_MODULE_COMPILE_CONFIG_DIRECTORY") == null,
            "unavailable-runtime behavior runs only without the separately provisioned live runtime")
        val root = Path.of("build/test-tmp").toAbsolutePath().normalize()
        Files.createDirectories(root)
        val project = Files.createTempDirectory(root, "module-runtime-unavailable-")
        try { action(project) } finally {
            Files.walk(project).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
    }

    private fun model() = RecoveredProgramModel(inputSha256 = "a".repeat(64), functions = listOf(
        RecoveredFunction("fn_alpha", "alpha_run", 0x1000UL, "int alpha_run(void)",
            "int alpha_run(void) { return 7; }"),
    ))
}
