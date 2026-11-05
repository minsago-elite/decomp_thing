package decompengine.builtin

import decompengine.agent.AgentCancellation
import decompengine.agent.AgentExecutionLimits
import decompengine.builtin.provider.*
import decompengine.chatgpt.ChatGptDeadline
import decompengine.chatgpt.ChatGptDeadlineClock
import decompengine.chatgpt.ChatGptOperationFence
import decompengine.project.GeneratedCValidationBudgetPolicy
import decompengine.project.GeneratedCValidationHostSafetyLimits
import decompengine.repair.RepairResourceBudget
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.time.Duration
import java.util.Collections
import java.util.IdentityHashMap
import java.util.UUID
import java.util.concurrent.atomic.AtomicReference

internal fun v2Fail(kind: ModelFailureKind = ModelFailureKind.INVALID_REQUEST): Nothing = throw ModelProviderException(kind)
internal fun v2Require(value: Boolean) { if (!value) v2Fail() }
internal fun v2Capacity(value: Boolean) { if (!value) v2Fail(ModelFailureKind.RESOURCE_EXHAUSTED) }
internal fun v2Add(a: Long, b: Long): Long = try { Math.addExact(a, b) } catch (_: ArithmeticException) { v2Fail(ModelFailureKind.RESOURCE_EXHAUSTED) }
internal fun v2Subtract(a: Long, b: Long): Long = try { Math.subtractExact(a, b) } catch (_: ArithmeticException) { v2Fail(ModelFailureKind.RESOURCE_EXHAUSTED) }
internal fun v2Multiply(a: Long, b: Long): Long = try { Math.multiplyExact(a, b) } catch (_: ArithmeticException) { v2Fail(ModelFailureKind.RESOURCE_EXHAUSTED) }
internal fun v2Nanos(value: Duration): Long {
    v2Require(!value.isNegative && !value.isZero)
    return try { value.toNanos() } catch (_: ArithmeticException) { v2Fail(ModelFailureKind.RESOURCE_EXHAUSTED) }
}
internal fun v2BytesDigest(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
/** Length-prefix every field; no ambiguous concatenation, locale, map iteration, or DTO toString. */
internal fun v2Digest(fields: List<String>): String {
    val digest = MessageDigest.getInstance("SHA-256")
    fields.forEach { field ->
        val bytes = field.toByteArray(Charsets.UTF_8)
        digest.update(ByteBuffer.allocate(4).putInt(bytes.size).array()); digest.update(bytes)
    }
    return digest.digest().joinToString("") { "%02x".format(it) }
}
/** Counts before allocating encoded copies. Invalid UTF-16 never becomes replacement characters. */
internal fun v2Utf8Bytes(text: String, ceiling: Long): Long {
    var count = 0L; var i = 0
    while (i < text.length) {
        val c = text[i++]
        val bytes = when {
            c.code < 0x80 -> 1L
            c.code < 0x800 -> 2L
            c.isHighSurrogate() -> { v2Require(i < text.length && text[i].isLowSurrogate()); i++; 4L }
            c.isLowSurrogate() -> v2Fail()
            else -> 3L
        }
        count = v2Add(count, bytes); v2Capacity(count <= ceiling)
    }
    return count
}

internal enum class PlanBudgetPolicyV1 { LOCAL_ACCEPTANCE_V1 }
internal class PlanRunSelectionV1(val accountId: UUID, val modelSlug: String, val budgetPolicy: PlanBudgetPolicyV1) {
    init { v2Require(modelSlug.matches(Regex("[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}"))) }
    override fun toString() = "PlanRunSelectionV1(redacted)"
}
internal sealed interface GenerationRequirementV2 {
    data class RequireServerOutputCap(val tokens: Int) : GenerationRequirementV2 { init { v2Require(tokens > 0) } }
    data class ElectLocalAcceptance(val policyVersion: Int = 1) : GenerationRequirementV2
}

/** Local acceptance units are always estimates, never a promise about server tokens. */
internal data class LocalBudgetV1(
    val inputUnits: Long = 1_000_000,
    val outputUnits: Long = 128_000,
    val maxRequests: Int = 64,
    val maxToolActions: Int = 256,
    val callsPerResponse: Int = 32,
    val requestBytes: Long = 2L * 1024 * 1024,
    val responseBytes: Long = 4L * 1024 * 1024,
    val eventBytes: Long = 256L * 1024,
    val contextBytes: Long = 2L * 1024 * 1024,
    val historyReserveBytes: Long = contextBytes / 4,
    val continuationBytes: Long = contextBytes,
    val toolResultBytes: Long = 256L * 1024,
    val receivedBytesTotal: Long = 8L * 1024 * 1024,
    val displayedBytesTotal: Long = 8L * 1024 * 1024,
    val evidenceBytes: Long = 32L * 1024 * 1024,
    val privateDiskBytes: Long = 32L * 1024 * 1024,
    val maxIdenticalAction: Int = 3,
    val traceRecords: Long = 4096,
    val wallClock: Duration = Duration.ofMinutes(20),
    val overallTimeout: Duration = Duration.ofMinutes(3),
    val connectTimeout: Duration = Duration.ofSeconds(10),
    val requestTimeout: Duration = Duration.ofSeconds(60),
    val idleTimeout: Duration = Duration.ofSeconds(30),
    val maxRetries: Int = 2,
) {
    init {
        v2Require(listOf(inputUnits, outputUnits, requestBytes, responseBytes, eventBytes, contextBytes,
            historyReserveBytes, continuationBytes, toolResultBytes, receivedBytesTotal, displayedBytesTotal,
            evidenceBytes, privateDiskBytes, traceRecords).all { it > 0 })
        v2Require(maxRequests > 0 && maxToolActions > 0 && callsPerResponse in 1..32 && maxIdenticalAction > 0 && maxRetries in 0..10)
        v2Require(listOf(requestBytes, responseBytes, eventBytes, contextBytes, continuationBytes, toolResultBytes).all { it <= Int.MAX_VALUE })
        v2Require(eventBytes <= responseBytes && toolResultBytes <= contextBytes && continuationBytes <= contextBytes && historyReserveBytes < contextBytes && historyReserveBytes >= contextBytes / 4)
        listOf(wallClock, overallTimeout, connectTimeout, requestTimeout, idleTimeout).forEach { v2Nanos(it) }
    }
    internal fun fields(): List<String> = listOf(inputUnits, outputUnits, maxRequests, maxToolActions, callsPerResponse,
        requestBytes, responseBytes, eventBytes, contextBytes, historyReserveBytes, continuationBytes, toolResultBytes,
        receivedBytesTotal, displayedBytesTotal, evidenceBytes, privateDiskBytes, maxIdenticalAction, traceRecords,
        v2Nanos(wallClock), v2Nanos(overallTimeout), v2Nanos(connectTimeout), v2Nanos(requestTimeout), v2Nanos(idleTimeout), maxRetries).map { it.toString() }
}
internal data class CallerRequirementsV2(val legacyLimits: AgentExecutionLimits, val localLimits: LocalBudgetV1)
internal data class HostAdmissionLimitsV2(val local: LocalBudgetV1, val validation: GeneratedCValidationHostSafetyLimits)
internal data class ProfileAdmissionLimitsV2(val local: LocalBudgetV1, val validation: RepairResourceBudget)
internal class RunCommitmentsV2(val request: String, val workflow: String, val profile: String, val source: String, val toolPolicy: String) {
    init { v2Require(fields().all { it.matches(Regex("[a-f0-9]{64}")) }) }
    internal fun fields() = listOf(request, workflow, profile, source, toolPolicy)
    override fun toString() = "RunCommitmentsV2(redacted)"
}
/** Synthetic immutable identity seam; this is not a credential store or a token lease. */
internal class AccountBindingV2(
    val accountId: UUID, val issuer: String, val hostId: UUID, val issuedClient: String,
    val verifiedSubjectCommitment: String, val authEpoch: Long, val modelSlug: String,
) {
    init {
        v2Require(issuer == "https://auth.openai.com" && issuedClient.matches(Regex("oaiapp_[A-Za-z0-9_-]{1,192}")))
        v2Require(verifiedSubjectCommitment.matches(Regex("[a-f0-9]{64}")) && authEpoch >= 0)
        v2Require(modelSlug.matches(Regex("[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}")))
    }
    internal fun commitment() = v2Digest(listOf(accountId.toString(), issuer, hostId.toString(), issuedClient, verifiedSubjectCommitment, authEpoch.toString(), modelSlug))
    override fun toString() = "AccountBindingV2(redacted)"
}
internal fun interface NanoClockV2 { fun now(): Long }
internal data class CallTimeoutsV2(val overallNanos: Long, val connectNanos: Long, val requestNanos: Long, val idleNanos: Long)
/** Captured by the future host ingress before queue/helper work. No credentials or callbacks. */
internal class OriginalModelRunOperationV2 private constructor(
    private val root: ChatGptDeadline,
    private val fence: ChatGptOperationFence,
    private val system: Boolean,
) {
    private val owner = AtomicReference<ModelRunAdmissionV2?>()
    fun cancel() = fence.cancel()
    fun tightenFrom(entryNanos: Long, remainingNanos: Long) = root.tightenFrom(entryNanos, remainingNanos)
    internal fun claim(admission: ModelRunAdmissionV2) {
        requireLive(root)
        v2Require(owner.compareAndSet(null, admission))
    }
    internal fun child(admission: ModelRunAdmissionV2, span: Long): ChatGptDeadline {
        v2Require(owner.get() === admission)
        return root.capFromOrigin(span)
    }
    internal fun validate(child: ChatGptDeadline, expectedFence: ChatGptOperationFence, requireSystem: Boolean) {
        v2Require(system == requireSystem && (root.clock === ChatGptDeadlineClock.SYSTEM) == requireSystem)
        v2Require(child.isWithin(root) && expectedFence === fence)
        requireLive(child)
    }
    internal fun requireLive(child: ChatGptDeadline): Long {
        v2Require(child.isWithin(root))
        if (fence.isCancelled()) v2Fail(ModelFailureKind.CANCELLED)
        val left = child.remainingNanos()
        if (left <= 0) v2Fail(ModelFailureKind.TIMEOUT)
        return left
    }
    internal fun sharedFence() = fence
    override fun toString() = "OriginalModelRunOperationV2(redacted)"
    companion object {
        fun captureSystem(originalAllowance: Duration): OriginalModelRunOperationV2 =
            capture(ChatGptDeadlineClock.SYSTEM, originalAllowance, true)
        fun captureControlledForTest(clock: ChatGptDeadlineClock, originalAllowance: Duration): OriginalModelRunOperationV2 {
            v2Require(clock !== ChatGptDeadlineClock.SYSTEM)
            return capture(clock, originalAllowance, false)
        }
        private fun capture(clock: ChatGptDeadlineClock, allowance: Duration, system: Boolean): OriginalModelRunOperationV2 =
            OriginalModelRunOperationV2(ChatGptDeadline.start(clock, minOf(v2Nanos(allowance), 1_200_000_000_000L)),
                ChatGptOperationFence(), system)
    }
}

/** Time/cancellation only. This record never grants credentials, dispatch or settlement. */
internal class ModelRunDeadlineAuthorityV2 private constructor(
    private val original: OriginalModelRunOperationV2,
    val deadline: ChatGptDeadline,
    val fence: ChatGptOperationFence,
) {
    internal fun remainingNanos(): Long = original.requireLive(deadline)
    internal fun requireAuthority(expected: OriginalModelRunOperationV2, system: Boolean): ModelRunDeadlineAuthorityV2 {
        v2Require(expected === original)
        original.validate(deadline, fence, system)
        return this
    }
    override fun toString() = "ModelRunDeadlineAuthorityV2(redacted)"
    companion object {
        internal fun fromOriginal(original: OriginalModelRunOperationV2, owner: ModelRunAdmissionV2, span: Long) =
            ModelRunDeadlineAuthorityV2(original, original.child(owner, span), original.sharedFence())
    }
}

internal class RunDeadlineV2 private constructor(
    private val authority: ModelRunDeadlineAuthorityV2?,
    private val end: Long,
    private val clock: NanoClockV2?,
    private val cancellation: AgentCancellation?,
) {
    /** OFFLINE_COMPATIBILITY: callback clocks never acquire SYSTEM or TEST authority. */
    internal constructor(end: Long, clock: NanoClockV2, cancellation: AgentCancellation) : this(null, end, clock, cancellation)
    fun remainingNanos(): Long {
        authority?.let { return it.remainingNanos() }
        if (cancellation!!.isCancellationRequested()) v2Fail(ModelFailureKind.CANCELLED)
        val left = v2Subtract(end, clock!!.now())
        if (left <= 0) v2Fail(ModelFailureKind.TIMEOUT)
        return left
    }
    fun requireSystemAuthority(expectedOriginal: OriginalModelRunOperationV2): ModelRunDeadlineAuthorityV2 =
        (authority ?: v2Fail()).requireAuthority(expectedOriginal, true)
    fun requireTestAuthority(expectedOriginal: OriginalModelRunOperationV2): ModelRunDeadlineAuthorityV2 =
        (authority ?: v2Fail()).requireAuthority(expectedOriginal, false)
    /** Final admission check: deliberately cannot invoke an offline callback. */
    internal fun requireTrustedLive() { authority?.remainingNanos() }
    fun callTimeouts(budget: LocalBudgetV1): CallTimeoutsV2 {
        val overall = minOf(remainingNanos(), v2Nanos(budget.overallTimeout))
        return CallTimeoutsV2(overall, minOf(overall, v2Nanos(budget.connectTimeout)),
            minOf(overall, v2Nanos(budget.requestTimeout)), minOf(overall, v2Nanos(budget.idleTimeout)))
    }
    override fun toString() = "RunDeadlineV2(redacted)"
    companion object {
        internal fun fromOriginal(original: OriginalModelRunOperationV2, owner: ModelRunAdmissionV2, span: Long) =
            RunDeadlineV2(ModelRunDeadlineAuthorityV2.fromOriginal(original, owner, span), 0L, null, null)
    }
}
internal class CheckedAdmissionV2 private constructor(
    internal val owner: Any, internal val selection: PlanRunSelectionV1?, val requirement: GenerationRequirementV2,
    val budget: LocalBudgetV1, val capabilities: ProviderCapabilitiesV2, val tools: FrozenToolRegistryV2,
    val commitments: RunCommitmentsV2, val deadline: RunDeadlineV2, val limitsDigest: String, val policyDigest: String,
) {
    override fun toString() = "CheckedAdmissionV2(redacted)"
    companion object {
        internal fun mint(owner: Any, selection: PlanRunSelectionV1?, requirement: GenerationRequirementV2, budget: LocalBudgetV1,
            capabilities: ProviderCapabilitiesV2, tools: FrozenToolRegistryV2, commitments: RunCommitmentsV2, deadline: RunDeadlineV2, validationCommitment: String) =
            CheckedAdmissionV2(owner, selection, requirement, budget, capabilities, tools, commitments, deadline,
                v2Digest(budget.fields()), v2Digest(listOf("provider-v2/local-acceptance-v1/codec-1", capabilities.commitment()) +
                    budget.fields() + commitments.fields() + tools.commitment + (when (requirement) {
                        is GenerationRequirementV2.RequireServerOutputCap -> listOf("server-cap", requirement.tokens.toString())
                        is GenerationRequirementV2.ElectLocalAcceptance -> listOf("local-acceptance", requirement.policyVersion.toString())
                    }) + validationCommitment))
    }
}
internal class AdmittedModelRunV2 private constructor(val runId: UUID, internal val checked: CheckedAdmissionV2, val binding: AccountBindingV2) {
    val budget get() = checked.budget
    val tools get() = checked.tools
    val deadline get() = checked.deadline
    val limitsDigest get() = checked.limitsDigest
    val bindingCommitment = binding.commitment()
    val policyDigest = v2Digest(listOf(checked.policyDigest, bindingCommitment))
    internal fun claimLedger() = (checked.owner as ModelRunAdmissionV2).claimLedger(this)
    override fun toString() = "AdmittedModelRunV2(redacted)"
    companion object { internal fun mint(checked: CheckedAdmissionV2, binding: AccountBindingV2) = AdmittedModelRunV2(UUID.randomUUID(), checked, binding) }
}

/** No credentials/catalog/HTTP/tool-open callbacks exist in phase one. Registry is pure metadata. */
internal class ModelRunAdmissionV2 private constructor(
    private val registry: () -> List<ToolDefinitionV2>,
    private val commitments: RunCommitmentsV2,
    private val clock: NanoClockV2?,
    private val originalDeadlineNanos: Long,
    private val cancellation: AgentCancellation?,
    private val original: OriginalModelRunOperationV2?,
) {
    /** Preserved offline constructor; production callers must retain an original operation. */
    internal constructor(registry: () -> List<ToolDefinitionV2>, commitments: RunCommitmentsV2,
        clock: NanoClockV2, originalDeadlineNanos: Long, cancellation: AgentCancellation = AgentCancellation.NONE) :
        this(registry, commitments, clock, originalDeadlineNanos, cancellation, null)

    private val admissionLock = Any()
    private class Reservation { var poisoned = false }
    private var active: Reservation? = null
    private var currentCheck: CheckedAdmissionV2? = null
    private var finalRun: AdmittedModelRunV2? = null
    // Every access to these collections and reservation state holds admissionLock.

    private val bound = Collections.newSetFromMap(IdentityHashMap<CheckedAdmissionV2, Boolean>())
    private val issuedChecks = Collections.newSetFromMap(IdentityHashMap<CheckedAdmissionV2, Boolean>())
    private val issuedRuns = IdentityHashMap<AdmittedModelRunV2, Boolean>()
    private fun rejectOverlap() {
        active?.let { it.poisoned = true; v2Fail() }
    }
    private fun reserve(validate: () -> Unit): Reservation = synchronized(admissionLock) {
        rejectOverlap()
        validate() // private callback-free state predicates only
        Reservation().also { active = it }
    }
    private fun compare(token: Reservation) { v2Require(active === token && !token.poisoned) }
    private fun release(token: Reservation) = synchronized(admissionLock) {
        if (active === token) active = null
    }
    private fun requireBindable(checked: CheckedAdmissionV2) {
        v2Require(checked.owner === this && checked in issuedChecks && checked !in bound)
        if (original != null) v2Require(finalRun == null && currentCheck === checked)
    }
    fun checkCapabilities(selection: PlanRunSelectionV1?, requirement: GenerationRequirementV2,
        compiledCapabilities: ProviderCapabilitiesV2, caller: CallerRequirementsV2,
        host: HostAdmissionLimitsV2, profile: ProfileAdmissionLimitsV2): CheckedAdmissionV2 {
        val token = reserve { if (original != null) v2Require(finalRun == null) }
        try {
            return checkCandidate(token, selection, requirement, compiledCapabilities, caller, host, profile)
        } finally { release(token) }
    }
    private fun checkCandidate(token: Reservation, selection: PlanRunSelectionV1?, requirement: GenerationRequirementV2,
        compiledCapabilities: ProviderCapabilitiesV2, caller: CallerRequirementsV2,
        host: HostAdmissionLimitsV2, profile: ProfileAdmissionLimitsV2): CheckedAdmissionV2 {
        val expected = when (compiledCapabilities.providerId) {
            "chatgpt-plan" -> ProviderCapabilitiesV2.siwc()
            "offline-fake-hard-cap" -> ProviderCapabilitiesV2.fakeHardCap()
            else -> v2Fail(ModelFailureKind.UNSUPPORTED_FEATURE)
        }
        if (compiledCapabilities.commitment() != expected.commitment()) v2Fail(ModelFailureKind.UNSUPPORTED_FEATURE)
        when (requirement) {
            is GenerationRequirementV2.RequireServerOutputCap -> {
                if (selection != null || compiledCapabilities.serverOutputCap != ServerOutputCapV2.SUPPORTED) v2Fail(ModelFailureKind.UNSUPPORTED_FEATURE)
                // V2 cannot promise a server input cap; the legacy explicit output promise must fit.
                if (caller.legacyLimits.maxInputTokens != null ||
                    caller.legacyLimits.maxOutputTokens?.let { requirement.tokens.toLong() > it } == true) v2Fail(ModelFailureKind.UNSUPPORTED_FEATURE)
            }
            is GenerationRequirementV2.ElectLocalAcceptance -> {
                if (selection == null || requirement.policyVersion != 1 || selection.budgetPolicy != PlanBudgetPolicyV1.LOCAL_ACCEPTANCE_V1 ||
                    caller.legacyLimits.maxInputTokens != null || caller.legacyLimits.maxOutputTokens != null) v2Fail(ModelFailureKind.UNSUPPORTED_FEATURE)
            }
        }
        val validationCommitment = v2Digest(listOf(canonicalToolJsonV2(
            GeneratedCValidationBudgetPolicy(host.validation).admit(profile.validation)))) // rejection, never inference clamping
        val candidates = listOf(LocalBudgetV1(), caller.localLimits, host.local, profile.local)
        fun n(f: (LocalBudgetV1) -> Long) = candidates.minOf(f)
        fun i(f: (LocalBudgetV1) -> Int) = candidates.minOf(f)
        fun d(f: (LocalBudgetV1) -> Duration) = candidates.minOf(f)
        val legacy = caller.legacyLimits
        v2Nanos(legacy.wallClockTimeout); v2Nanos(legacy.idleTimeout)
        val context = minOf(n { it.contextBytes }, profile.validation.maximumContextBytes)
        val effective = LocalBudgetV1(
            inputUnits = n { it.inputUnits }, outputUnits = n { it.outputUnits }, maxRequests = minOf(i { it.maxRequests }, legacy.maxTurns),
            maxToolActions = minOf(i { it.maxToolActions }, legacy.maxToolCalls), callsPerResponse = i { it.callsPerResponse },
            requestBytes = minOf(n { it.requestBytes }, profile.validation.maximumRequestBytes),
            responseBytes = minOf(n { it.responseBytes }, profile.validation.maximumResponseBytes),
            eventBytes = minOf(n { it.eventBytes }, profile.validation.maximumResponseBytes), contextBytes = context,
            historyReserveBytes = maxOf(context / 4, candidates.maxOf { v2Add(v2Multiply(context, it.historyReserveBytes), it.contextBytes - 1) / it.contextBytes }),
            continuationBytes = minOf(n { it.continuationBytes }, context), toolResultBytes = minOf(n { it.toolResultBytes }, context),
            receivedBytesTotal = n { it.receivedBytesTotal }, displayedBytesTotal = minOf(n { it.displayedBytesTotal }, legacy.maxOutputBytes),
            evidenceBytes = minOf(n { it.evidenceBytes }, profile.validation.maximumIndexEvidenceBytes),
            privateDiskBytes = n { it.privateDiskBytes }, maxIdenticalAction = i { it.maxIdenticalAction }, traceRecords = n { it.traceRecords },
            wallClock = minOf(d { it.wallClock }, legacy.wallClockTimeout), overallTimeout = d { it.overallTimeout },
            connectTimeout = d { it.connectTimeout }, requestTimeout = d { it.requestTimeout },
            idleTimeout = minOf(d { it.idleTimeout }, legacy.idleTimeout), maxRetries = i { it.maxRetries })
        val deadline = if (original != null) RunDeadlineV2.fromOriginal(original, this, v2Nanos(effective.wallClock))
            else RunDeadlineV2(minOf(originalDeadlineNanos, v2Add(clock!!.now(), v2Nanos(effective.wallClock))), clock, cancellation!!)
        deadline.remainingNanos()
        val tools = FrozenToolRegistryV2.freeze(registry(), minOf(effective.requestBytes, effective.contextBytes))
        val candidate = CheckedAdmissionV2.mint(this, selection, requirement, effective, compiledCapabilities, tools, commitments, deadline, validationCommitment)
        return synchronized(admissionLock) {
            compare(token)
            if (original != null) v2Require(finalRun == null)
            deadline.requireTrustedLive()
            issuedChecks.add(candidate)
            if (original != null) currentCheck = candidate
            candidate
        }
    }
    internal fun claimLedger(run: AdmittedModelRunV2) = synchronized(admissionLock) {
        rejectOverlap()
        if (original != null) v2Require(finalRun === run)
        v2Require(issuedRuns[run] == false)
        issuedRuns[run] = true
    }
    fun bind(checked: CheckedAdmissionV2, immutableAccountBinding: AccountBindingV2): AdmittedModelRunV2 {
        val token = reserve { requireBindable(checked) }
        try {
            checked.selection?.let { v2Require(it.accountId == immutableAccountBinding.accountId && it.modelSlug == immutableAccountBinding.modelSlug) }
            checked.deadline.remainingNanos()
            val candidate = AdmittedModelRunV2.mint(checked, immutableAccountBinding)
            return synchronized(admissionLock) {
                compare(token)
                requireBindable(checked)
                checked.deadline.requireTrustedLive()
                bound.add(checked)
                issuedRuns[candidate] = false
                if (original != null) finalRun = candidate
                candidate
            }
        } finally { release(token) }
    }
    companion object {
        fun fromOriginal(registry: () -> List<ToolDefinitionV2>, commitments: RunCommitmentsV2,
            original: OriginalModelRunOperationV2): ModelRunAdmissionV2 =
            ModelRunAdmissionV2(registry, commitments, null, 0L, null, original).also { original.claim(it) }
    }
}
