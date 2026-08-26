package decompengine.repair

import decompengine.agent.AgentCancellation
import decompengine.agent.AgentExecutionEvent
import decompengine.agent.AgentExecutionLimits
import decompengine.agent.AgentHarness
import java.nio.file.Path

/**
 * Trusted-host test access to production bridges.
 *
 * Reflection is intentional here and nowhere in main: the production threat model treats
 * Reflection/Instrumentation/Unsafe inside the host JVM as a trusted-host compromise. Keeping the
 * bypass in the test artifact lets bytecode checks prove that main publishes no test constructor.
 */
internal object TestRepairRuntimeAccess {
    private val runtimeIdentity: Any by lazy {
        SecureRepairRuntime::class.java.getDeclaredField("RUNTIME_IDENTITY").let { field ->
            field.isAccessible = true
            field.get(null)
        }
    }

    private fun registeredProfile(profile: RepairIndexProfile): Any =
        SecureRepairRuntime::class.java.declaredClasses
            .single { it.simpleName == "RegisteredProfile" }
            .getDeclaredConstructor(String::class.java, RepairIndexProfile::class.java)
            .let { constructor ->
                constructor.isAccessible = true
                constructor.newInstance(profile.profileId(), profile)
            }

    private fun graphAuthority(profile: RepairIndexProfile): Any =
        SecureRepairRuntime::class.java.declaredClasses
            .single { it.simpleName == "GraphAuthority" }
            .getDeclaredConstructor(RepairIndexProfile::class.java)
            .let { constructor ->
                constructor.isAccessible = true
                constructor.newInstance(profile)
            }

    fun openGraph(
        projectDir: Path,
        profile: RepairIndexProfile,
        budget: RepairResourceBudget,
        faultInjector: ModuleRevisionFaultInjector?,
    ): ModuleRevisionGraph = ModuleRevisionGraph.openAuthorized(
        runtimeIdentity,
        graphAuthority(profile),
        projectDir,
        profile,
        budget,
        faultInjector,
    )

    fun loadIndex(
        projectDir: Path,
        profile: RepairIndexProfile,
        budget: RepairResourceBudget,
    ): ModuleRepairIndex = ModuleRepairIndex.loadAuthorized(
        runtimeIdentity,
        graphAuthority(profile),
        projectDir,
        profile,
        budget,
    )

    fun openLoop(
        harness: AgentHarness,
        history: RepairHistory,
        profile: RepairIndexProfile,
        validationStrategy: RepairValidationStrategy,
        stagingAuthority: RepairStagingAuthority,
        limits: AgentExecutionLimits,
        cancellation: AgentCancellation,
        onAgentEvent: (AgentExecutionEvent) -> Unit,
        resourceBudget: RepairResourceBudget,
        allowTestOnlyValidation: Boolean,
    ): TraceGuidedRepairLoop = TraceGuidedRepairLoop.openAuthorized(
        runtimeIdentity,
        harness,
        history,
        registeredProfile(profile),
        validationStrategy,
        stagingAuthority,
        limits,
        cancellation,
        onAgentEvent,
        resourceBudget,
        allowTestOnlyValidation,
    )
}

internal fun ModuleRevisionGraph.Companion.open(
    projectDir: Path,
    profile: RepairIndexProfile,
    budget: RepairResourceBudget = RepairResourceBudget(),
): ModuleRevisionGraph = TestRepairRuntimeAccess.openGraph(projectDir, profile, budget, null)

internal fun ModuleRevisionGraph.Companion.openForTesting(
    projectDir: Path,
    profile: RepairIndexProfile,
    budget: RepairResourceBudget = RepairResourceBudget(),
    faultInjector: ModuleRevisionFaultInjector,
): ModuleRevisionGraph = TestRepairRuntimeAccess.openGraph(projectDir, profile, budget, faultInjector)

internal fun ModuleRepairIndex.Companion.load(
    projectDir: Path,
    profile: RepairIndexProfile,
    budget: RepairResourceBudget = RepairResourceBudget(),
): ModuleRepairIndex = TestRepairRuntimeAccess.loadIndex(projectDir, profile, budget)

internal fun TraceGuidedRepairLoop.Companion.forTesting(
    harness: AgentHarness,
    history: RepairHistory,
    profile: RepairIndexProfile,
    validationStrategy: RepairValidationStrategy,
    stagingAuthority: RepairStagingAuthority,
    limits: AgentExecutionLimits = AgentExecutionLimits(),
    cancellation: AgentCancellation = AgentCancellation.NONE,
    onAgentEvent: (AgentExecutionEvent) -> Unit = {},
    resourceBudget: RepairResourceBudget = RepairResourceBudget(),
): TraceGuidedRepairLoop = TestRepairRuntimeAccess.openLoop(
    harness,
    history,
    profile,
    validationStrategy,
    stagingAuthority,
    limits,
    cancellation,
    onAgentEvent,
    resourceBudget,
    allowTestOnlyValidation = true,
)
