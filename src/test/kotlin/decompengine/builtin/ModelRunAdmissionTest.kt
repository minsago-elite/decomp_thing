package decompengine.builtin

import decompengine.agent.*
import decompengine.builtin.provider.*
import decompengine.project.GeneratedCValidationHostSafetyLimits
import decompengine.repair.RepairBudgetExceededException
import decompengine.repair.RepairResourceBudget
import java.time.Duration
import java.util.UUID
import kotlin.test.*

/** Shared offline fixtures only; no store, process, transport, filesystem or real credentials. */
internal class V2Fixture(
    val local: LocalBudgetV1 = LocalBudgetV1(),
    val legacy: AgentExecutionLimits = AgentExecutionLimits(),
    val hostLocal: LocalBudgetV1 = LocalBudgetV1(),
    val profileLocal: LocalBudgetV1 = LocalBudgetV1(),
    val validation: RepairResourceBudget = RepairResourceBudget(),
    val cancellation: AgentCancellation = AgentCancellation.NONE,
    val definitions: MutableList<ToolDefinitionV2> = mutableListOf(tool()),
) {
    var now = 0L
    var registryReads = 0
    var binderCalls = 0
    var tokenCalls = 0
    var catalogCalls = 0
    var httpCalls = 0
    var toolOpens = 0
    val account = UUID(1, 2)
    val path = ToolPathV2("project", "source.c")
    val policy = ToolRequestPolicyV2(mapOf(path to setOf(ToolOperationV2.READ, ToolOperationV2.WRITE)))
    val inventory = ToolInventoryV2(mapOf(path to "a".repeat(64)))
    val binding = AccountBindingV2(account, "https://auth.openai.com", UUID(3, 4), "oaiapp_fixture", "b".repeat(64), 1, "fixture-model")
    val selection = PlanRunSelectionV1(account, "fixture-model", PlanBudgetPolicyV1.LOCAL_ACCEPTANCE_V1)
    val factory = ModelRunAdmissionV2({ registryReads++; definitions }, RunCommitmentsV2("c".repeat(64), "d".repeat(64),
        "e".repeat(64), inventory.commitment, policy.commitment), NanoClockV2 { now }, Duration.ofMinutes(20).toNanos(), cancellation)
    fun check(selection: PlanRunSelectionV1? = this.selection,
        requirement: GenerationRequirementV2 = GenerationRequirementV2.ElectLocalAcceptance(),
        capabilities: ProviderCapabilitiesV2 = ProviderCapabilitiesV2.siwc()) =
        factory.checkCapabilities(selection, requirement, capabilities, CallerRequirementsV2(legacy, local),
            HostAdmissionLimitsV2(hostLocal, GeneratedCValidationHostSafetyLimits()), ProfileAdmissionLimitsV2(profileLocal, validation))
    fun bind(checked: CheckedAdmissionV2 = check()): AdmittedModelRunV2 { binderCalls++; return factory.bind(checked, binding) }
    fun fakeLaunch(selection: PlanRunSelectionV1? = this.selection,
        requirement: GenerationRequirementV2 = GenerationRequirementV2.ElectLocalAcceptance()): AdmittedModelRunV2 {
        val run = bind(check(selection, requirement))
        // Instrument every fake downstream effect; this creates no actual transport or tool session.
        tokenCalls++; catalogCalls++; httpCalls++; toolOpens++
        return run
    }
    fun rejectionCounters() = listOf(registryReads, binderCalls, tokenCalls, catalogCalls, httpCalls, toolOpens)
    companion object {
        fun tool(name: String = "write", schema: String = """{"type":"object","properties":{"path":{"type":"string"},"text":{"type":"string"}},"required":["path","text"],"additionalProperties":false}""") = ToolDefinitionV2(name, "offline fixture", schema)
    }
}

class ModelRunAdmissionTest {
    @Test fun `positive fake launch reaches all instrumented seams only after binding`() {
        val f = V2Fixture(); f.fakeLaunch()
        assertEquals(List(6) { 1 }, f.rejectionCounters())
    }
    @Test fun `hard cap rejection happens before every effect seam`() {
        val f = V2Fixture()
        val failure = assertFailsWith<ModelProviderException> { f.fakeLaunch(null, GenerationRequirementV2.RequireServerOutputCap(17)) }
        assertEquals(ModelFailureKind.UNSUPPORTED_FEATURE, failure.kind)
        assertEquals(List(6) { 0 }, f.rejectionCounters())
    }
    @Test fun `local election and legacy tokens are never silently translated`() {
        val fixtures = listOf(V2Fixture(), V2Fixture(legacy = AgentExecutionLimits(maxInputTokens = 1)),
            V2Fixture(legacy = AgentExecutionLimits(maxOutputTokens = 8192)))
        fixtures.forEachIndexed { index, f ->
            assertFailsWith<ModelProviderException> { f.fakeLaunch(if (index == 0) null else f.selection) }
            assertEquals(List(6) { 0 }, f.rejectionCounters())
        }
        val f = V2Fixture()
        assertFailsWith<ModelProviderException> { f.check(requirement = GenerationRequirementV2.ElectLocalAcceptance(2)) }
        assertEquals(0, f.registryReads)
    }
    @Test fun `compiled capability versions and SIWC hard cap cannot be forged`() {
        listOf(ProviderCapabilitiesV2("unknown"), ProviderCapabilitiesV2("chatgpt-plan", version = 1),
            ProviderCapabilitiesV2("chatgpt-plan", codecVersion = 2),
            ProviderCapabilitiesV2("chatgpt-plan", serverOutputCap = ServerOutputCapV2.SUPPORTED),
            ProviderCapabilitiesV2("chatgpt-plan", tools = "hosted"), ProviderCapabilitiesV2("chatgpt-plan", usage = "required")).forEach { cap ->
            val f = V2Fixture(); assertFailsWith<ModelProviderException> { f.check(capabilities = cap) }; assertEquals(0, f.registryReads)
        }
    }
    @Test fun `separate fake hard-cap declaration accepts only compatible requirement`() {
        val f = V2Fixture()
        val checked = f.check(null, GenerationRequirementV2.RequireServerOutputCap(8192), ProviderCapabilitiesV2.fakeHardCap())
        assertIs<GenerationRequirementV2.RequireServerOutputCap>(checked.requirement)
        assertEquals(8192, ModelCallLimits().maxOutputTokens) // V1 default remains an independent token requirement.
        assertEquals(1, MODEL_PROVIDER_CONTRACT_VERSION)
        assertFailsWith<ModelProviderException> { f.check(f.selection, GenerationRequirementV2.RequireServerOutputCap(8192), ProviderCapabilitiesV2.fakeHardCap()) }
        assertNotNull(V2Fixture().check(capabilities = ProviderCapabilitiesV2.fakeHardCap()))
    }
    @Test fun `binding pins exact account and model and checked permits are single use`() {
        val f = V2Fixture(); val checked = f.check()
        val wrong = AccountBindingV2(UUID(9, 9), f.binding.issuer, f.binding.hostId, f.binding.issuedClient,
            f.binding.verifiedSubjectCommitment, 1, f.binding.modelSlug)
        assertFailsWith<ModelProviderException> { f.factory.bind(checked, wrong) }
        val run = f.factory.bind(checked, f.binding)
        assertEquals(f.binding.commitment(), run.bindingCommitment)
        assertFailsWith<ModelProviderException> { f.factory.bind(checked, f.binding) }
        assertFailsWith<ModelProviderException> { V2Fixture().factory.bind(checked, f.binding) }
        assertEquals("AdmittedModelRunV2(redacted)", run.toString())
    }
    @Test fun `caller host profile and original deadline all tighten independent ceilings`() {
        val f = V2Fixture(local = LocalBudgetV1(maxRequests = 20),
            legacy = AgentExecutionLimits(maxTurns = 3, maxToolCalls = 4, maxOutputBytes = 55, idleTimeout = Duration.ofSeconds(2)),
            hostLocal = LocalBudgetV1(receivedBytesTotal = 99, inputUnits = 1000),
            profileLocal = LocalBudgetV1(maxRequests = 10, outputUnits = 200))
        val run = f.bind(); val b = run.budget
        assertEquals(3, b.maxRequests); assertEquals(4, b.maxToolActions)
        assertEquals(55L, b.displayedBytesTotal); assertEquals(99L, b.receivedBytesTotal)
        assertEquals(1000L, b.inputUnits); assertEquals(200L, b.outputUnits)
        assertEquals(Duration.ofSeconds(2).toNanos(), run.deadline.callTimeouts(b).idleNanos)
        f.now = Duration.ofMinutes(20).toNanos() - 7
        val times = run.deadline.callTimeouts(b)
        assertEquals(CallTimeoutsV2(7, 7, 7, 7), times)
        f.now += 7
        assertEquals(ModelFailureKind.TIMEOUT, assertFailsWith<ModelProviderException> { run.deadline.remainingNanos() }.kind)
    }
    @Test fun `all effective commitments are deterministic and identity bound`() {
        val a = V2Fixture().bind(); val b = V2Fixture().bind()
        assertEquals(a.limitsDigest, b.limitsDigest); assertEquals(a.policyDigest, b.policyDigest)
        assertNotEquals(a.policyDigest, V2Fixture(local = LocalBudgetV1(outputUnits = 17)).bind().policyDigest)
        assertNotEquals(a.limitsDigest, V2Fixture(local = LocalBudgetV1(outputUnits = 17)).bind().limitsDigest)
    }
    @Test fun `unsafe validation profile rejects rather than clamps`() {
        val f = V2Fixture(validation = RepairResourceBudget(maximumBehaviorExecutionMillis = 30_001))
        assertFailsWith<RepairBudgetExceededException> { f.check() }
        assertEquals(0, f.registryReads)
    }
    @Test fun `invalid numeric and duration relationships fail closed`() {
        listOf<() -> Any>({ LocalBudgetV1(outputUnits = 0) }, { LocalBudgetV1(inputUnits = -1) },
            { LocalBudgetV1(eventBytes = 5_000_000) }, { LocalBudgetV1(toolResultBytes = 3_000_000) },
            { LocalBudgetV1(historyReserveBytes = 2L * 1024 * 1024) },
            { LocalBudgetV1(wallClock = Duration.ofSeconds(Long.MAX_VALUE)) },
            { LocalBudgetV1(callsPerResponse = 33) }, { GenerationRequirementV2.RequireServerOutputCap(0) },
            { v2Add(Long.MAX_VALUE, 1) }, { v2Multiply(Long.MAX_VALUE, 6) }).forEach { assertFailsWith<ModelProviderException> { it() } }
        assertEquals(Long.MAX_VALUE, v2Add(Long.MAX_VALUE - 1, 1))
    }
    @Test fun `registry is frozen and duplicate unsupported schemas fail before bind`() {
        val f = V2Fixture(); val run = f.bind(); f.definitions.clear()
        assertEquals(1, run.tools.definitions.size)
        assertFailsWith<UnsupportedOperationException> { (run.tools.definitions as MutableList).clear() }
        listOf(mutableListOf(V2Fixture.tool(), V2Fixture.tool()), mutableListOf(V2Fixture.tool(schema = """{"type":"object","additionalProperties":true}""")),
            mutableListOf(V2Fixture.tool(name = "decomp.write"))).forEach { defs ->
            val broken = V2Fixture(definitions = defs); assertFailsWith<ModelProviderException> { broken.check() }; assertEquals(0, broken.binderCalls)
        }
    }
}
