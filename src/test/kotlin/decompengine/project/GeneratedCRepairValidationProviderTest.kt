package decompengine.project

import decompengine.agent.AgentCancellation
import decompengine.agent.AgentCancellationSource
import decompengine.repair.RepairResourceBudget
import decompengine.repair.RepairValidationAssurance
import decompengine.validation.SandboxUnavailableException
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
import java.util.concurrent.CancellationException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse

class GeneratedCRepairValidationProviderTest {
    @Test
    fun `registered production strategy refuses unqualified writable closure before filesystem mutation`() {
        val provider = GeneratedCRepairRuntimeProvider()
        assertEquals("generated-c-make-v1", provider.profileId())
        val strategy = provider.createValidationStrategy()
        assertEquals(RepairValidationAssurance.STRICT_CONTAINED, strategy.assurance)
        assertFailsWith<SandboxUnavailableException> { strategy.requireAvailable() }
        val absent = Path.of("/definitely-absent/generated-c-validation")
        assertFailsWith<SandboxUnavailableException> { strategy.compile(absent, absent.resolve("log"), RepairResourceBudget()) }
        assertFalse(Files.exists(absent))
    }

    @Test
    fun `runtime configuration rejects operator identity before parsing candidate supplied bytes`() {
        val directory = Files.createTempDirectory("generated-c-config-")
        val configuration = directory.resolve("runtime.json")
        try {
            Files.writeString(configuration, "{}")
            assertFailsWith<IllegalArgumentException> { GeneratedCRepairRuntimeConfiguration.load(configuration) }
        } finally {
            Files.delete(configuration)
            Files.delete(directory)
        }
    }

    @Test
    fun `deadline and cancellation remain independent required checks`() {
        val cancellation = AgentCancellationSource()
        val active = GeneratedCValidationDeadline.after(Duration.ofMinutes(1), cancellation.cancellation)
        active.check()
        cancellation.cancel()
        assertFailsWith<CancellationException> { active.check() }
        assertFailsWith<GeneratedCValidationTimeoutException> {
            GeneratedCValidationDeadline(System.nanoTime() - 1, AgentCancellation.NONE).check()
        }
    }
}
