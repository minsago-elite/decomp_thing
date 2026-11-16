package decompengine.project

import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertSame

class ModuleCompilationPolicyTest {
    @Test
    fun `registered profiles select contained compilation and retain explicit historical commands`() {
        for (profile in listOf(GeneratedCMakeReconstructionProfile.descriptor, GeneratedCNinjaReconstructionProfile.descriptor)) {
            val policy = ReconstructionCompilationPolicies.resolve(profile)
            assertSame(ContainedModuleCompilationPolicy, policy)
            assertEquals("generated-c-contained-module-compilation-v1", policy.id)
            assertEquals(listOf("authenticated-profile-compiler") + profile.adapterConfiguration.getValue("compiler-flags") +
                listOf("-c", "src/modules/sample.c", "-o", "<owned-module-object>"),
                policy.command(profile, "src/modules/sample.c"))
            assertEquals("generated-c-module-validation-v2", policy.fingerprintIdentity(6))
            assertEquals(policy.id, policy.fingerprintIdentity(7))
            assertEquals(GeneratedCModuleValidation.command(profile, "src/modules/sample.c"),
                policy.commandForCheckpoint(profile, "src/modules/sample.c", 6))
            assertFailsWith<IllegalArgumentException> { policy.command(profile, "sample.c") }
        }
    }

    @Test
    fun `contained policy refuses caller compiler overrides before runtime or filesystem access`() {
        for (base in listOf(GeneratedCMakeReconstructionProfile.descriptor, GeneratedCNinjaReconstructionProfile.descriptor)) {
            val selected = ReconstructionProfile(base.schemaVersion, base.id, base.layout, base.budgets,
                base.adapterConfiguration + ("compiler-driver" to listOf("/usr/bin/cc")))
            val policy = ReconstructionCompilationPolicies.resolve(selected)
            val parent = Files.createTempDirectory("selected-compiler-policy-")
            try {
                val project = parent.resolve("must-not-be-created")
                assertEquals("module compiler profile may vary only registered reconstruction budgets",
                    assertFailsWith<IllegalArgumentException> { policy.requireAvailable(selected) }.message)
                assertEquals("module compiler profile may vary only registered reconstruction budgets",
                    assertFailsWith<IllegalArgumentException> {
                        policy.validate(project, "src/modules/sample.c", selected)
                    }.message)
                assertFalse(Files.exists(project))
            } finally {
                parent.toFile().deleteRecursively()
            }
        }
    }

    @Test
    fun `unregistered profile cannot generate files or dispatch reconstruction`() {
        val base = GeneratedCMakeReconstructionProfile.descriptor
        val unsupported = ReconstructionProfile(base.schemaVersion, "unregistered-fixture-v1",
            base.layout, base.budgets, base.adapterConfiguration)
        assertFailsWith<IllegalArgumentException> {
            ReconstructionCompilationPolicies.resolve(unsupported)
        }
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
