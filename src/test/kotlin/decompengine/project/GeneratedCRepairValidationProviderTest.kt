package decompengine.project

import decompengine.agent.AgentCancellation
import decompengine.agent.AgentCancellationSource
import decompengine.repair.RepairCandidateValidationRequest
import decompengine.repair.RepairResourceBudget
import decompengine.repair.RepairBudgetExceededException
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
import kotlin.test.assertSame
import kotlin.test.assertTrue

class GeneratedCRepairValidationProviderTest {
    @Test
    fun `selected repair registration binds validation identity and source roles without alternate execution`() {
        val budget = RepairResourceBudget()
        val make = GeneratedCValidationProfile.registeredMake
        val provider = GeneratedCRepairRuntimeProvider()
        assertSame(make.indexProfile, provider.indexProfile())
        make.requireIdentity(provider.profileId(), provider.indexProfile().configurationSha256(budget), budget)
        make.requireSourceLayout(listOf("Makefile", "include/decomp_types.h", "src/main.c"), budget)
        val buildCommand = make.buildCommand(Path.of("/tools/make"), Path.of("/tools/cc"), Path.of("/tools/sh"))
        assertEquals("/tools/make", buildCommand.first())
        assertEquals("Makefile", buildCommand[buildCommand.indexOf("-f") + 1])

        val ninja = GeneratedCValidationRegistration(GeneratedCNinjaReconstructionProfile.descriptor)
        ninja.requireIdentity(ninja.indexProfile.profileId(), ninja.indexProfile.configurationSha256(budget), budget)
        ninja.requireSourceLayout(listOf("build.ninja", "include/decomp_types.h", "src/main.c"), budget)
        assertFailsWith<IllegalArgumentException> {
            ninja.requireSourceLayout(listOf("Makefile", "include/decomp_types.h", "src/main.c"), budget)
        }
        assertFailsWith<IllegalArgumentException> { LinuxGeneratedCRepairValidationBoundary.create(ninja) }
        val ninjaCommand = ninja.buildCommand(Path.of("/tools/ninja"), Path.of("/tools/cc"), Path.of("/tools/sh"))
        assertEquals(listOf("/tools/ninja", "-f", "build.ninja", "build/reconstructed"), ninjaCommand)
        assertFailsWith<IllegalArgumentException> {
            ninja.buildCommand(Path.of("/tools/make"), Path.of("/tools/cc"), Path.of("/tools/sh"))
        }

        val base = GeneratedCMakeReconstructionProfile.descriptor
        val relocated = ReconstructionProfile(base.schemaVersion, base.id,
            ProjectLayoutProfile(base.layout.schemaVersion, base.layout.declarations.map { declaration ->
                val path = when (declaration.id) {
                    "build-definition" -> "config/build/Makefile"
                    else -> declaration.pathTemplate
                        .replace(Regex("^src/"), "workspace/code/")
                        .replace(Regex("^include/"), "workspace/headers/")
                }
                ProjectFileDeclaration(declaration.id, path, declaration.roles, declaration.contentKind)
            }), base.budgets, base.adapterConfiguration)
        val relocatedRegistration = GeneratedCValidationRegistration(relocated)
        val relocatedPaths = listOf("config/build/Makefile", "workspace/code/main.c",
            "workspace/headers/decomp_types.h").sorted()
        relocatedRegistration.requireSourceLayout(relocatedPaths, budget)
        assertTrue(relocatedRegistration.sources.isEditable("workspace/code/main.c"))
        assertFalse(relocatedRegistration.sources.isEditable("workspace/code/undeclared.c"))
        assertFailsWith<IllegalArgumentException> {
            relocatedRegistration.requireSourceLayout(listOf("Makefile", "src/main.c"), budget)
        }
        assertFailsWith<IllegalArgumentException> {
            LinuxGeneratedCRepairValidationBoundary.create(relocatedRegistration)
        }
        val relocatedCommand = relocatedRegistration.buildCommand(Path.of("/tools/make"),
            Path.of("/tools/cc"), Path.of("/tools/sh"))
        assertEquals("config/build/Makefile", relocatedCommand[relocatedCommand.indexOf("-f") + 1])
    }

    @Test
    fun `behavior validation admits profile limits only beneath independent host ceilings`() {
        val selected = RepairResourceBudget(maximumBehaviorExecutionMillis = 2_000,
            maximumBehaviorStdoutBytes = 1_024, maximumBehaviorStderrBytes = 1_024,
            maximumBehaviorOutputBytes = 2_048)
        val policy = GeneratedCValidationBudgetPolicy(GeneratedCValidationHostSafetyLimits(
            maximumStdoutBytes = 2_048, maximumStderrBytes = 2_048,
            maximumOutputBytes = 4_096, maximumExecutionMillis = 3_000))
        val evidence = policy.admit(selected)
        assertEquals(evidence.getValue("profileLimits"), evidence.getValue("effectiveLimits"))
        assertFalse(evidence.getValue("profileLimits") == evidence.getValue("hostSafetyLimits"))
        assertFailsWith<RepairBudgetExceededException> {
            policy.admit(selected.copy(maximumBehaviorExecutionMillis = 3_001))
        }
        assertFailsWith<RepairBudgetExceededException> {
            policy.admit(selected.copy(maximumBehaviorStdoutBytes = 4_097,
                maximumBehaviorOutputBytes = 4_097))
        }
        assertFailsWith<RepairBudgetExceededException> {
            GeneratedCValidationBudgetPolicy.DEFAULT.admit(RepairResourceBudget(
                maximumBehaviorOutputBytes = 16L * 1024 * 1024 + 1))
        }
    }

    @Test
    fun `validation identity policy admits only the registered descriptor fingerprint`() {
        val budget = RepairResourceBudget()
        val current = GeneratedCRepairIndexProfile
        GeneratedCValidationProfile.requireIdentity(current.profileId(), current.configurationSha256(), budget)
        val tighterBehavior = budget.copy(maximumBehaviorExecutionMillis = budget.maximumBehaviorExecutionMillis - 1)
        assertFalse(current.configurationSha256(tighterBehavior) == current.configurationSha256(budget))
        assertFailsWith<IllegalArgumentException> {
            GeneratedCValidationProfile.requireIdentity(current.profileId(), current.configurationSha256(), tighterBehavior)
        }
        GeneratedCValidationProfile.requireIdentity(current.profileId(),
            current.configurationSha256(tighterBehavior), tighterBehavior)
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
