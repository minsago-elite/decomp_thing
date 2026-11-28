package decompengine.builtin.provider

import decompengine.builtin.*
import java.util.Collections

/** Offline contract only. Deliberately unrelated to ModelProvider and its version constant. */
internal interface ModelProviderV2 {
    fun capabilities(): ProviderCapabilitiesV2
    fun generate(call: AdmittedModelCallV2, sink: ModelEventV2Sink): ModelResponseV2
}

internal enum class ServerOutputCapV2 { SUPPORTED, UNAVAILABLE }
internal class ProviderCapabilitiesV2 internal constructor(
    val providerId: String,
    val version: Int = 2,
    val codecVersion: Int = 1,
    val serverOutputCap: ServerOutputCapV2 = ServerOutputCapV2.UNAVAILABLE,
    val tools: String = "namespaced-functions-v1",
    val continuation: String = "responses-items-v1",
    val usage: String = "optional-terminal-usage-v1",
) {
    internal fun commitment() = v2Digest(listOf(providerId, version.toString(), codecVersion.toString(),
        serverOutputCap.name, tools, continuation, usage))
    override fun toString() = "ProviderCapabilitiesV2(redacted)"
    companion object {
        fun siwc() = ProviderCapabilitiesV2("chatgpt-plan")
        /** Test capability, never registered with a production factory. */
        internal fun fakeHardCap() = ProviderCapabilitiesV2("offline-fake-hard-cap", serverOutputCap = ServerOutputCapV2.SUPPORTED)
    }
}

internal fun interface ModelEventV2Sink { fun emit(event: ModelEventV2) }
/** Events are display-only; none can debit a ledger, settle a lease, or authorize a tool. */
internal sealed interface ModelEventV2 {
    class TextDelta(val text: String) : ModelEventV2 { override fun toString() = "TextDeltaV2(redacted)" }
    class Finished(val reason: ModelFinishReason) : ModelEventV2
}

internal class ModelMessageV2(val role: ModelRole, val content: String, val continuation: ValidatedResponsesTurnV1? = null) {
    init { v2Require(continuation == null || role == ModelRole.ASSISTANT) }
    override fun toString() = "ModelMessageV2(redacted)"
}

/** Input is the complete bounded serialization, not a V1 request or a bearer-bearing carrier. */
internal class AdmittedModelCallV2 internal constructor(
    val run: AdmittedModelRunV2,
    val ordinal: Int,
    val attempt: Int,
    encodedInput: ByteArray,
    val meter: AttemptMeterV2,
    val timeouts: CallTimeoutsV2,
) {
    private val input = encodedInput.copyOf()
    fun encodedInput(): ByteArray = input.copyOf()
    val encodedInputBytes: Long get() = input.size.toLong()
    override fun toString() = "AdmittedModelCallV2(redacted)"
}

/** C owns strict wire parsing and is the only future producer of this internal handle.
 * These bytes are private context, never archive/journal evidence or replay authority.
 */
internal class ValidatedResponsesTurnV1 internal constructor(
    internal val call: AdmittedModelCallV2,
    val responseId: String,
    orderedItems: List<ByteArray>,
    proposals: List<ToolProposalV2>,
    val neutralTextCallsSha256: String,
) {
    private val items: List<ByteArray>
    val proposals: List<ToolProposalV2>
    val rawBytes: Long
    val sha256: String
    val bindingSha256 = call.run.bindingCommitment
    val toolsSha256 = call.run.tools.commitment
    init {
        v2Require(responseId.matches(Regex("[A-Za-z0-9_-]{1,128}")))
        v2Require(neutralTextCallsSha256.matches(Regex("[a-f0-9]{64}")))
        v2Require(orderedItems.size in 1..1024)
        var total = 0L
        orderedItems.forEach {
            v2Require(it.isNotEmpty() && it.size.toLong() <= call.run.budget.eventBytes)
            total = v2Add(total, it.size.toLong())
        }
        v2Capacity(total <= call.run.budget.continuationBytes)
        v2Capacity(proposals.size <= call.run.budget.callsPerResponse)
        rawBytes = total
        items = Collections.unmodifiableList(orderedItems.map { it.copyOf() })
        this.proposals = Collections.unmodifiableList(ArrayList(proposals))
        sha256 = v2Digest(items.map { v2BytesDigest(it) })
    }
    fun orderedItems(): List<ByteArray> = Collections.unmodifiableList(items.map { it.copyOf() })
    override fun toString() = "ValidatedResponsesTurnV1(redacted)"
}

/** Completion is necessary but not sufficient: the host must settle this exact call first. */
internal class ModelResponseV2 internal constructor(
    val text: String,
    val finishReason: ModelFinishReason,
    val continuation: ValidatedResponsesTurnV1,
    val reported: ReportedModelUsageV1?,
) {
    override fun toString() = "ModelResponseV2(redacted)"
}
