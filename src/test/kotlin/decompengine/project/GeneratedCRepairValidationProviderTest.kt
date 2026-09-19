package decompengine.project

import decompengine.agent.AgentCancellation
import decompengine.agent.AgentCancellationSource
import decompengine.repair.RepairCandidateValidationRequest
import decompengine.repair.RepairResourceBudget
import decompengine.repair.RepairValidationAssurance
import decompengine.repair.repairCandidateSourceSha256
import decompengine.repair.repairRegressionCorpusSha256
import decompengine.validation.SandboxUnavailableException
import decompengine.validation.ProcessInput
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
import java.util.concurrent.CancellationException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class GeneratedCRepairValidationProviderTest {
    @Test
    fun `validation identity policy admits only the registered descriptor fingerprint`() {
        val budget = RepairResourceBudget()
        val current = GeneratedCRepairIndexProfile
        GeneratedCValidationProfile.requireIdentity(current.profileId(), current.configurationSha256(), budget)
        val base = GeneratedCMakeReconstructionProfile.descriptor
        val changed = ReconstructionProfile(base.schemaVersion, base.id, base.layout,
            base.budgets.copy(buildWallClockMillis = base.budgets.buildWallClockMillis - 1), base.adapterConfiguration)
        val otherPolicies = listOf(
            GeneratedCRepairIndexProfile.forProfile(changed),
            GeneratedCRepairIndexProfile.forProfile(GeneratedCNinjaReconstructionProfile.descriptor),
        )
        for (other in otherPolicies) {
            assertFailsWith<IllegalArgumentException> {
                GeneratedCValidationProfile.requireIdentity(other.profileId(), other.configurationSha256(), budget)
            }
        }
        assertFailsWith<IllegalArgumentException> {
            GeneratedCValidationProfile.requireIdentity(current.profileId(), sha256(current.profileId().toByteArray()), budget)
        }
    }

    @Test
    fun `validation source policy agrees with index recovery permissions`() {
        val budget = RepairResourceBudget()
        val paths = listOf("Makefile", "include/decomp_types.h", "src/modules/alpha.c", "src/unlisted.c")
        val policy = GeneratedCValidationProfile.sources
        val editable = paths.filter(policy::isEditable)
        assertFalse("src/unlisted.c" in editable)
        assertTrue("src/modules/alpha.c" in editable)
        assertTrue(GeneratedCRepairIndexProfile.authorizesRecoveryLayout(paths, editable, budget))
        GeneratedCValidationProfile.requireSourceLayout(paths, budget)
        assertFalse(GeneratedCRepairIndexProfile.authorizesRecoveryLayout(paths, paths, budget))
        assertFailsWith<IllegalArgumentException> {
            GeneratedCValidationProfile.requireSourceLayout(paths.drop(1), budget)
        }
    }

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

    @Test
    fun `source and retained corpus accounting are independent and detached`() {
        val source = mapOf("Makefile" to "0123456789".toByteArray())
        val inputs = listOf(ProcessInput("case", stdin = "abcdef".toByteArray()))
        val budget = RepairResourceBudget(
            maximumSourceFiles = 1,
            maximumSourceFileBytes = 10,
            maximumSourceBytes = 10,
            maximumRegressionInputBytes = 10,
            maximumRequestBytes = 11,
            maximumContextFiles = 1,
            maximumContextBytes = 10,
            maximumStagingDirectories = 1,
            maximumStagingBytes = 10,
            maximumPatchFiles = 1,
            maximumPatchBytes = 10,
            maximumStoredBlobBytes = 10,
        )
        fun request(withBudget: RepairResourceBudget) = RepairCandidateValidationRequest(
            projectDir = Path.of(".").toAbsolutePath(),
            candidateSources = source,
            sourceRevisionSha256 = repairCandidateSourceSha256(source),
            profileId = "generated-c-make-v1",
            profileSha256 = "a".repeat(64),
            indexSha256 = "b".repeat(64),
            originalBinary = null,
            inputs = inputs,
            regressionCorpusSha256 = repairRegressionCorpusSha256(inputs),
            reportsDir = Path.of("reports"),
            label = "issue-702-contract",
            budget = withBudget,
            deadlineNanos = Long.MAX_VALUE,
            cancellation = AgentCancellation.NONE,
        )

        val accepted = request(budget)
        val detachedSource = accepted.candidateSources.getValue("Makefile")
        detachedSource[0] = 'x'.code.toByte()
        val detachedStdin = accepted.inputs.single().stdin
        detachedStdin[0] = 'x'.code.toByte()
        assertEquals('0'.code.toByte(), accepted.candidateSources.getValue("Makefile")[0])
        assertEquals('a'.code.toByte(), accepted.inputs.single().stdin[0])
        assertFailsWith<IllegalArgumentException> {
            request(budget.copy(
                maximumSourceFileBytes = 9,
                maximumSourceBytes = 9,
                maximumContextBytes = 9,
                maximumStagingBytes = 9,
                maximumPatchBytes = 9,
                maximumStoredBlobBytes = 9,
            ))
        }
        assertFailsWith<IllegalArgumentException> {
            request(budget.copy(maximumRegressionInputBytes = 9, maximumRequestBytes = 10))
        }
    }
}
