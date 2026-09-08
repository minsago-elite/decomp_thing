package decompengine.project

import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ModuleCompilationPolicyTest {
    @Test
    fun `registered profile selects one compiler policy and preserves configured driver`() {
        val base = GeneratedCMakeReconstructionProfile.descriptor
        val selected = ReconstructionProfile(base.schemaVersion, base.id, base.layout, base.budgets,
            base.adapterConfiguration + ("compiler-driver" to listOf("/usr/bin/cc")))
        val policy = ReconstructionCompilationPolicies.resolve(selected)
        assertEquals("generated-c-module-validation-v2", policy.id)
        assertEquals("/usr/bin/cc", policy.command(selected, "src/modules/sample.c").first())
        val project = Files.createTempDirectory("selected-compiler-policy-")
        val source = project.resolve("sample.c")
        Files.writeString(source, "int sample(void) { return 7; }\n")
        val result = policy.validate(project, "sample.c", selected)
        assertTrue(result.passed)
        assertEquals(sha256(Files.readAllBytes(source)), result.sourceSha256)
    }

    @Test
    fun `unregistered profile cannot generate files or dispatch reconstruction`() {
        val base = GeneratedCMakeReconstructionProfile.descriptor
        val unsupported = ReconstructionProfile(base.schemaVersion, "unregistered-fixture-v1",
            base.layout, base.budgets, base.adapterConfiguration)
        val project = Files.createTempDirectory("unsupported-profile-").resolve("project")
        var calls = 0
        val model = RecoveredProgramModel(inputSha256 = "a".repeat(64), functions = emptyList())
        assertFailsWith<IllegalArgumentException> {
            SourceTreeGenerator.generate(model, project, profile = unsupported,
                reconstructor = ModuleReconstructor { calls++; error("must not dispatch") })
        }
        assertEquals(0, calls)
        assertFalse(Files.exists(project))
    }
}
