package decompengine.chatgpt.operator

import decompengine.chatgpt.*
import decompengine.builtin.*
import decompengine.builtin.provider.ProviderCapabilitiesV2
import decompengine.builtin.ToolDefinitionV2
import decompengine.agent.AgentExecutionLimits
import decompengine.project.GeneratedCValidationHostSafetyLimits
import decompengine.repair.RepairResourceBudget
import java.time.Duration
import java.time.Instant
import java.util.Collections
import java.util.UUID
import kotlinx.serialization.json.*

/** Safe operator failures are closed, fixed and never contain rejected input or exception text. */
internal enum class OperatorFailureV1 {
    INVALID_REQUEST, NOT_FOUND, STALE_ACCOUNT, ATTEMPT_IN_PROGRESS, ATTEMPT_NOT_READY, ATTEMPT_USED,
    IDEMPOTENCY_CONFLICT, LOCAL_CALLBACK_REQUIRED, NEEDS_SIGN_IN, SCOPE_DENIED, MODEL_UNAVAILABLE,
    STRICT_CAP_UNSUPPORTED, POLICY_REQUIRED, REFRESH_UNCERTAIN, RATE_LIMIT, UNAVAILABLE, TIMEOUT,
    CANCELLED, CLEANUP_UNSETTLED, AMBIGUOUS_SEND, RESOURCE_LIMIT,
}

internal sealed interface OperatorResultV1<out T> {
    class Ok<T>(val value: T) : OperatorResultV1<T>
    class Failed(val code: OperatorFailureV1) : OperatorResultV1<Nothing>
}

internal class OperatorOwnerV1 private constructor(val kind: Kind, private val identity: UUID) {
    internal enum class Kind { WEB_SESSION, CLI }
    internal fun same(other: OperatorOwnerV1) = kind == other.kind && identity == other.identity
    override fun toString() = "OperatorOwnerV1(redacted)"
    companion object { internal fun mintFromCoordinator(kind: Kind) = OperatorOwnerV1(kind, UUID.randomUUID()) }
}
internal object OperatorOwnerIssuerV1 {
    internal fun cli() = OperatorOwnerV1.mintFromCoordinator(OperatorOwnerV1.Kind.CLI)
    internal fun webSession() = OperatorOwnerV1.mintFromCoordinator(OperatorOwnerV1.Kind.WEB_SESSION)
}

internal data class AccountStampV1(val accountId: String, val authEpoch: Long, val generation: Long) {
    init { require(canonicalUuid(accountId) && authEpoch >= 0 && generation >= 0) }
}
internal data class OperatorVersionV1(val operatorRevision: Long, val accountId: String? = null, val authEpoch: Long? = null, val generation: Long? = null) {
    init { require(operatorRevision >= 0 && (accountId == null) == (authEpoch == null) && (accountId == null) == (generation == null) && (accountId == null || canonicalUuid(accountId)) && (authEpoch == null || authEpoch >= 0) && (generation == null || generation >= 0)) }
}
internal enum class SignInPhaseV1 { PREPARING, WAITING_FOR_BROWSER, EXCHANGING, COMMITTING, SUCCEEDED, FAILED, CANCELLED, EXPIRED, COMMIT_UNKNOWN, CLEANUP_PENDING }

internal class WelcomeNoticeV1 private constructor(val noticeId: UUID, val accountId: String, val version: Int) {
    init { require(canonicalUuid(accountId) && version == 1) }
    override fun toString() = "WelcomeNoticeV1(redacted)"
    companion object { internal fun mint(accountId: String) = WelcomeNoticeV1(UUID.randomUUID(), accountId, 1) }
}
internal class PlanAccountViewV1(account: ChatGptPlanAccount, val version: OperatorVersionV1, val welcome: WelcomeNoticeV1?) {
    val account: ChatGptPlanAccount = account.copy(scopes = Collections.unmodifiableSet(account.scopes.toSet()))
    init {
        require(this.account.accountId.matches(Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")))
        require(this.account.issuer == "https://auth.openai.com" && this.account.clientId.matches(Regex("oaiapp_[A-Za-z0-9_-]{1,192}")))
        require(this.account.label.length <= 120 && (this.account.email?.length ?: 0) <= 254 && this.account.authEpoch >= 0 && this.account.generation >= 0)
        v2Utf8Bytes(this.account.label, 512); this.account.email?.let { v2Utf8Bytes(it, 1024) }
        require(this.account.scopes.size <= 32 && this.account.scopes.all { it.matches(Regex("[A-Za-z0-9._:-]{1,128}")) })
        require(this.account.selectedModel == null || this.account.selectedModel.matches(Regex("[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}")))
        require(version.accountId == this.account.accountId && version.authEpoch == this.account.authEpoch && version.generation == this.account.generation)
    }
    override fun toString() = "PlanAccountViewV1(accountState=${account.state}, redacted)"
}
internal class OperatorStatusV1(accounts: List<PlanAccountViewV1>, val selectedAccountId: String?, val operatorRevision: Long,
    val available: Boolean, val unavailableReason: OperatorFailureV1?) {
    val accounts: List<PlanAccountViewV1> = Collections.unmodifiableList(accounts.toList())
    init {
        require(accounts.size <= 64 && operatorRevision >= 0 && (available || unavailableReason != null))
        require(selectedAccountId == null || canonicalUuid(selectedAccountId))
        require(accounts.map { it.account.accountId }.distinct().size == accounts.size)
    }
    override fun toString() = "OperatorStatusV1(accounts=${accounts.size}, redacted)"
}
internal class SignInStatusV1(val attemptId: UUID, val phase: SignInPhaseV1, val expiresAt: Instant,
    val account: PlanAccountViewV1? = null, val failure: OperatorFailureV1? = null,
    val cancelResult: ChatGptAuthCancelResult? = null, val commit: ChatGptAuthCommitState? = null,
    val cleanup: ChatGptAuthSettlement? = null, val version: Long = 0) {
    init { require(version >= 0) }
    override fun toString() = "SignInStatusV1(phase=$phase, redacted)"
}
internal class SignInLaunchV1 private constructor(val status: SignInStatusV1, internal val request: ChatGptPlanOAuthAttempt.AuthorizationRequest) : ChatGptAuthSafeObject() {
    internal fun authorizationUriForTrustedLauncher(): String = request.uri
    companion object { internal fun issue(status: SignInStatusV1, request: ChatGptPlanOAuthAttempt.AuthorizationRequest) = SignInLaunchV1(status, request) }
}
internal data class PlanModelViewV1(val slug: String, val displayName: String)
internal class CatalogViewV1(val account: AccountStampV1, val catalogId: UUID, val fetchedAt: Instant,
    val expiresAt: Instant, models: List<PlanModelViewV1>, val version: OperatorVersionV1) {
    val models: List<PlanModelViewV1> = Collections.unmodifiableList(models.toList())
    init {
        require(models.size <= 512 && models.map { it.slug }.distinct().size == models.size)
        require(models.all { it.slug.matches(Regex("[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}") ) && it.displayName.length <= 200 })
        models.forEach { v2Utf8Bytes(it.displayName, 800) }
        require(account.accountId.matches(Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")) && account.authEpoch >= 0 && account.generation >= 0)
        require(version.accountId == account.accountId && version.authEpoch == account.authEpoch && version.generation == account.generation)
        require(expiresAt.isAfter(fetchedAt) && Duration.between(fetchedAt, expiresAt) <= Duration.ofMinutes(5))
    }
    override fun toString() = "CatalogViewV1(models=${models.size}, redacted)"
}
internal enum class RemoteRevokeV1 { CONFIRMED, UNKNOWN, NOT_ATTEMPTED }
internal class SignOutViewV1(val account: PlanAccountViewV1, val localCredentialsCleared: Boolean,
    val remoteRevoke: RemoteRevokeV1, val cleanup: ChatGptAuthSettlement?) {
    override fun toString() = "SignOutViewV1(localCleared=$localCredentialsCleared, remoteRevoke=$remoteRevoke, redacted)"
}
internal class PlanDoctorViewV1(val authMode: String, val available: Boolean, val reason: OperatorFailureV1?,
    val selectedAccountId: String?, val state: ChatGptPlanAccount.State?, val privateRootPermissionsValid: Boolean?, val callbackProfile: String) {
    init { require(authMode == "chatgpt-plan" && callbackProfile == "same-host-loopback" && (available || reason != null)) }
    override fun toString() = "PlanDoctorViewV1(authMode=$authMode, available=$available, reason=$reason, redacted)"
}

private fun canonicalUuid(value: String): Boolean = runCatching { UUID.fromString(value).toString() == value }.getOrDefault(false)

internal interface ChatGptPlanOperatorPortV1 {
    fun status(owner: OperatorOwnerV1): OperatorResultV1<OperatorStatusV1>
    fun beginSignIn(owner: OperatorOwnerV1, target: ChatGptAuthorizationTarget, expected: OperatorVersionV1, requestKey: String): OperatorResultV1<SignInStatusV1>
    fun takeSignInLaunch(owner: OperatorOwnerV1, attemptId: UUID): OperatorResultV1<SignInLaunchV1>
    fun signInStatus(owner: OperatorOwnerV1, attemptId: UUID): OperatorResultV1<SignInStatusV1>
    fun cancelSignIn(owner: OperatorOwnerV1, attemptId: UUID): OperatorResultV1<SignInStatusV1>
    fun select(owner: OperatorOwnerV1, accountId: String, expected: OperatorVersionV1): OperatorResultV1<OperatorStatusV1>
    fun refreshCatalog(owner: OperatorOwnerV1, accountId: String, expected: OperatorVersionV1): OperatorResultV1<CatalogViewV1>
    fun setModel(owner: OperatorOwnerV1, accountId: String, slug: String, catalogId: UUID, expected: OperatorVersionV1): OperatorResultV1<PlanAccountViewV1>
    fun refreshAccount(owner: OperatorOwnerV1, accountId: String, expected: OperatorVersionV1): OperatorResultV1<PlanAccountViewV1>
    fun signOut(owner: OperatorOwnerV1, accountId: String, expected: OperatorVersionV1): OperatorResultV1<SignOutViewV1>
    fun acknowledgeWelcome(owner: OperatorOwnerV1, noticeId: UUID, expected: OperatorVersionV1): OperatorResultV1<PlanAccountViewV1>
    fun doctor(owner: OperatorOwnerV1): OperatorResultV1<PlanDoctorViewV1>
}

/** Exact public wire shape. Decimal strings prevent JSON-number precision loss. */
data class ChatGptLocalLimitsV1(
    val inputUnits: Long, val outputUnits: Long, val maxRequests: Int, val maxToolActions: Int, val callsPerResponse: Int,
    val requestBytes: Long, val responseBytes: Long, val eventBytes: Long, val contextBytes: Long,
    val historyReserveBytes: Long, val continuationBytes: Long, val toolResultBytes: Long,
    val receivedBytesTotal: Long, val displayedBytesTotal: Long, val evidenceBytes: Long, val privateDiskBytes: Long,
    val maxIdenticalAction: Int, val traceRecords: Long, val wallClockMs: Long, val overallTimeoutMs: Long,
    val connectTimeoutMs: Long, val requestTimeoutMs: Long, val idleTimeoutMs: Long, val maxRetries: Int,
) {
    internal fun toLocalBudget(): LocalBudgetV1 {
        require(maxRetries in 0..10 && callsPerResponse in 1..32)
        fun positive(v: Long) = require(v > 0)
        listOf(inputUnits, outputUnits, requestBytes, responseBytes, eventBytes, contextBytes, historyReserveBytes,
            continuationBytes, toolResultBytes, receivedBytesTotal, displayedBytesTotal, evidenceBytes, privateDiskBytes,
            traceRecords, wallClockMs, overallTimeoutMs, connectTimeoutMs, requestTimeoutMs, idleTimeoutMs).forEach(::positive)
        require(maxRequests > 0 && maxToolActions > 0 && maxIdenticalAction > 0)
        fun millis(v: Long): Duration { val d = Duration.ofMillis(v); d.toNanos(); return d }
        return LocalBudgetV1(inputUnits, outputUnits, maxRequests, maxToolActions, callsPerResponse,
            requestBytes, responseBytes, eventBytes, contextBytes, historyReserveBytes, continuationBytes,
            toolResultBytes, receivedBytesTotal, displayedBytesTotal, evidenceBytes, privateDiskBytes,
            maxIdenticalAction, traceRecords, millis(wallClockMs), millis(overallTimeoutMs), millis(connectTimeoutMs),
            millis(requestTimeoutMs), millis(idleTimeoutMs), maxRetries)
    }
    companion object {
        private fun millis(d: Duration): Long {
            val nanos = d.toNanos()
            require(nanos > 0 && nanos % 1_000_000L == 0L)
            return nanos / 1_000_000L
        }
        internal fun from(b: LocalBudgetV1) = ChatGptLocalLimitsV1(b.inputUnits,b.outputUnits,b.maxRequests,b.maxToolActions,b.callsPerResponse,
            b.requestBytes,b.responseBytes,b.eventBytes,b.contextBytes,b.historyReserveBytes,b.continuationBytes,b.toolResultBytes,
            b.receivedBytesTotal,b.displayedBytesTotal,b.evidenceBytes,b.privateDiskBytes,b.maxIdenticalAction,b.traceRecords,
            millis(b.wallClock),millis(b.overallTimeout),millis(b.connectTimeout),millis(b.requestTimeout),millis(b.idleTimeout),b.maxRetries)
    }
}
data class ChatGptPlanRunElectionV1(val accountId: String, val modelSlug: String, val budgetPolicy: String,
    val policyVersion: Int, val acceptedLocalLimits: Boolean, val expectedAuthEpoch: Long,
    val expectedGeneration: Long, val catalogId: String, val requestedLimits: ChatGptLocalLimitsV1)
internal data class ChatGptPlanAdmissionCaptureV1(val electionSha256: String, val effectiveLimits: ChatGptLocalLimitsV1,
    val invocationId: String, val bindingCommitment: String, val admittedAuthEpoch: Long, val admittedGeneration: Long,
    val limitsDigest: String, val policyDigest: String, val requestCommitment: String, val workflowCommitment: String,
    val profileCommitment: String, val sourceCommitment: String, val toolPolicyCommitment: String)

// Exact-object registration is in-memory fake composition only. Weak keys avoid retaining runs;
// the immutable value has no reference back to the key and cannot be installed by capture callers.
private data class BoundElectionV1(val digest: String, val stamp: AccountStampV1, val capture: ChatGptPlanAdmissionCaptureV1)
private val boundPlanElections = java.util.WeakHashMap<AdmittedModelRunV2, BoundElectionV1>()

internal fun capturePlanAdmission(election: ChatGptPlanRunElectionV1, trustedStamp: AccountStampV1,
    run: AdmittedModelRunV2): ChatGptPlanAdmissionCaptureV1 {
    val digest = canonicalElectionDigest(election)
    return synchronized(boundPlanElections) {
        val bound = requireNotNull(boundPlanElections[run]) { "Unregistered ChatGPT plan admission." }
        require(bound.digest == digest && bound.stamp == trustedStamp)
        bound.capture
    }
}

private fun canonicalElectionDigest(election: ChatGptPlanRunElectionV1): String {
    val requested = election.requestedLimits
    val limits = listOf(requested.inputUnits, requested.outputUnits, requested.maxRequests, requested.maxToolActions, requested.callsPerResponse,
        requested.requestBytes, requested.responseBytes, requested.eventBytes, requested.contextBytes, requested.historyReserveBytes,
        requested.continuationBytes, requested.toolResultBytes, requested.receivedBytesTotal, requested.displayedBytesTotal,
        requested.evidenceBytes, requested.privateDiskBytes, requested.maxIdenticalAction, requested.traceRecords, requested.wallClockMs,
        requested.overallTimeoutMs, requested.connectTimeoutMs, requested.requestTimeoutMs, requested.idleTimeoutMs, requested.maxRetries)
    val names = listOf("inputUnits","outputUnits","maxRequests","maxToolActions","callsPerResponse","requestBytes","responseBytes","eventBytes","contextBytes","historyReserveBytes","continuationBytes","toolResultBytes","receivedBytesTotal","displayedBytesTotal","evidenceBytes","privateDiskBytes","maxIdenticalAction","traceRecords","wallClockMs","overallTimeoutMs","connectTimeoutMs","requestTimeoutMs","idleTimeoutMs","maxRetries")
    val limitJson = JsonObject(names.zip(limits).associate { (name, value) -> name to JsonPrimitive(value.toString()) })
    val electionJson = buildJsonObject {
        put("accountId", election.accountId); put("modelSlug", election.modelSlug); put("budgetPolicy", election.budgetPolicy)
        put("policyVersion", election.policyVersion.toString()); put("acceptedLocalLimits", election.acceptedLocalLimits)
        put("expectedAuthEpoch", election.expectedAuthEpoch.toString()); put("expectedGeneration", election.expectedGeneration.toString())
        put("catalogId", election.catalogId); put("requestedLimits", limitJson)
    }
    val bytes = decompengine.oracle.core.OracleJson.canonicalBytes(electionJson,
        decompengine.oracle.core.StrictJsonLimits(4096, 4096, 8, 256, 128, 2048, 32))
    return decompengine.builtin.v2BytesDigest(bytes)
}

private fun bindElection(election: ChatGptPlanRunElectionV1, digest: String, trustedStamp: AccountStampV1,
    run: AdmittedModelRunV2): AdmittedModelRunV2 {
    require(election.budgetPolicy == "local-acceptance-v1" && election.policyVersion == 1 && election.acceptedLocalLimits)
    require(election.accountId == trustedStamp.accountId && election.expectedAuthEpoch == trustedStamp.authEpoch && election.expectedGeneration == trustedStamp.generation)
    require(run.binding.accountId.toString() == election.accountId && run.binding.authEpoch == election.expectedAuthEpoch && run.binding.modelSlug == election.modelSlug)
    val selection = run.checked.selection ?: throw IllegalArgumentException("Invalid ChatGPT plan election.")
    require(selection.accountId.toString() == election.accountId && selection.modelSlug == election.modelSlug &&
        selection.budgetPolicy == PlanBudgetPolicyV1.LOCAL_ACCEPTANCE_V1 && run.checked.requirement == GenerationRequirementV2.ElectLocalAcceptance(1))
    val commitments = run.checked.commitments.fields()
    val capture = ChatGptPlanAdmissionCaptureV1(digest, ChatGptLocalLimitsV1.from(run.budget),
        run.runId.toString(), run.bindingCommitment, run.binding.authEpoch, trustedStamp.generation, run.limitsDigest, run.policyDigest,
        commitments[0], commitments[1], commitments[2], commitments[3], commitments[4])
    synchronized(boundPlanElections) {
        check(run !in boundPlanElections)
        boundPlanElections[run] = BoundElectionV1(digest, trustedStamp, capture)
    }
    return run
}

internal fun admitPlanElection(election: ChatGptPlanRunElectionV1, capabilities: ProviderCapabilitiesV2,
    caller: CallerRequirementsV2, host: HostAdmissionLimitsV2, profile: ProfileAdmissionLimitsV2,
    commitments: RunCommitmentsV2, toolDefinitions: () -> List<ToolDefinitionV2>, clock: NanoClockV2, originalDeadlineNanos: Long,
    cancellation: decompengine.agent.AgentCancellation = decompengine.agent.AgentCancellation.NONE,
    trustedStamp: AccountStampV1, trustedCatalog: CatalogViewV1, now: Instant,
    binding: AccountBindingV2): AdmittedModelRunV2 {
    require(election.budgetPolicy == "local-acceptance-v1" && election.policyVersion == 1 && election.acceptedLocalLimits)
    val id = UUID.fromString(election.accountId); require(id.toString() == election.accountId)
    require(election.expectedAuthEpoch == binding.authEpoch && election.modelSlug == binding.modelSlug && id == binding.accountId)
    require(trustedStamp.accountId == election.accountId && trustedStamp.authEpoch == election.expectedAuthEpoch && trustedStamp.generation == election.expectedGeneration)
    val catalogId = UUID.fromString(election.catalogId).also { require(it.toString() == election.catalogId) }
    require(trustedCatalog.account == trustedStamp && trustedCatalog.catalogId == catalogId && trustedCatalog.models.any { it.slug == election.modelSlug })
    require(!now.isBefore(trustedCatalog.fetchedAt) && now.isBefore(trustedCatalog.expiresAt) &&
        java.time.Duration.between(trustedCatalog.fetchedAt, trustedCatalog.expiresAt) <= java.time.Duration.ofMinutes(5))
    val requested = election.requestedLimits.toLocalBudget()
    val digest = canonicalElectionDigest(election)
    val selection = PlanRunSelectionV1(id, election.modelSlug, PlanBudgetPolicyV1.LOCAL_ACCEPTANCE_V1)
    val requirement = GenerationRequirementV2.ElectLocalAcceptance(1)
    val admissionStart = clock.now()
    // C1 has three local envelopes. First resolve caller/host/profile with actual C1 and no
    // supplied tool effect, then intersect the elected envelope with that checked result.
    // In particular, history reserve is a proportional floor, NOT an ordinary scalar minimum.
    // Staged ceiling division may conservatively reserve an extra byte; it never relaxes a floor.
    val envelope = ModelRunAdmissionV2({ emptyList() }, commitments, clock, originalDeadlineNanos, cancellation)
        .checkCapabilities(selection, requirement, capabilities, caller, host, profile)
    val deadline = minOf(originalDeadlineNanos, Math.addExact(admissionStart, envelope.budget.wallClock.toNanos()))
    val engine = ModelRunAdmissionV2(toolDefinitions, commitments, clock, deadline, cancellation)
    val checked = engine.checkCapabilities(selection, requirement, capabilities,
        CallerRequirementsV2(caller.legacyLimits, requested), HostAdmissionLimitsV2(envelope.budget, host.validation), profile)
    // Register before exposing the actual run. Capture is a lookup, never a relabeling operation.
    return bindElection(election, digest, trustedStamp, engine.bind(checked, binding))
}
