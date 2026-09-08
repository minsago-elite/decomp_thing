package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Host-owned trigger and durable authorization callbacks, never a worker-issued capability. */
internal class KotlinContainedCommandInterruption(
    policyBytes: ByteArray,
    private val pollTrigger: () -> ByteArray?,
    private val authorizeDurably: (ByteArray) -> Unit,
) {
    private val policy = snapshotObject(policyBytes)
    val policySha256: String = OracleArtifacts.sha256(policy)
    private var requestSha256: String? = null
    private var poisoned = false
    private var inPoll = false
    private var authorization: ByteArray? = null
    private var delivered = false
    private var selectedKeeperPid: Long? = null

    @Synchronized
    fun bind(request: KotlinContainedCommandRequest) {
        check(!poisoned && requestSha256 == null) { "interruption controller is already bound or poisoned" }
        require(request.allowInterruption) { "interruption controller requires a v2 request" }
        requestSha256 = request.sha256
    }

    @Synchronized
    fun pollAndDeliver(
        request: KotlinContainedCommandRequest,
        secret: ByteArray,
        keeperPid: Long,
        publish: (ByteArray) -> Unit,
    ) {
        check(!poisoned && !inPoll && requestSha256 == request.sha256) { "interruption controller binding is not current" }
        if (delivered) return
        inPoll = true
        try {
            val observed = pollTrigger() ?: return
            val trigger = snapshotObject(observed)
            val token = KotlinContainedCommandProtocol.interrupt(secret, request, keeperPid)
            val unsigned = JsonObject(mapOf(
                "provider" to JsonPrimitive("kotlin-contained-command-interrupt-authorization-v1"),
                "schemaVersion" to JsonPrimitive(1),
                "requestSha256" to JsonPrimitive(request.sha256),
                "keeperPid" to JsonPrimitive(keeperPid),
                "policySha256" to JsonPrimitive(policySha256),
                "policy" to OracleJson.parseCanonical(policy, LIMITS),
                "triggerSha256" to JsonPrimitive(OracleArtifacts.sha256(trigger)),
                "trigger" to OracleJson.parseCanonical(trigger, LIMITS),
                "interruptSha256" to JsonPrimitive(OracleArtifacts.sha256(token)),
                "complete" to JsonPrimitive(false),
                "releaseEligible" to JsonPrimitive(false),
            ))
            val record = OracleJson.canonicalBytes(JsonObject(unsigned + ("authorizationSha256" to
                JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(unsigned, RECORD_LIMITS))))), RECORD_LIMITS)
            // A failed journal write must never deliver a token; a failed delivery is never retried.
            authorizeDurably(record.copyOf())
            authorization = record
            selectedKeeperPid = keeperPid
            publish(token.copyOf())
            delivered = true
        } catch (failure: Throwable) {
            poisoned = true
            throw failure
        } finally {
            inPoll = false
        }
    }

    @Synchronized
    fun requireInterruptedOutcome(outcome: KotlinContainedCommandOutcome): ByteArray {
        check(!poisoned && delivered) { "interruption was not delivered by this controller" }
        require(outcome.status == "INTERRUPTED" && outcome.keeperPid == selectedKeeperPid) { "contained command ended without the requested interruption" }
        return checkNotNull(authorization).copyOf()
    }

    companion object {
        private val LIMITS = StrictJsonLimits(maximumInputBytes = 4096, maximumCanonicalBytes = 4096,
            maximumDepth = 8, maximumNodes = 256, maximumStringBytes = 2048, maximumTotalStringBytes = 4096)
        private val RECORD_LIMITS = StrictJsonLimits(maximumInputBytes = 16384, maximumCanonicalBytes = 16384,
            maximumDepth = 12, maximumNodes = 1024, maximumStringBytes = 2048, maximumTotalStringBytes = 12288)

        private fun snapshotObject(bytes: ByteArray): ByteArray {
            require(bytes.size in 1..4096) { "interruption policy or trigger exceeds its byte bound" }
            val copy = bytes.copyOf()
            require(OracleJson.parseCanonical(copy, LIMITS) is JsonObject) { "interruption policy or trigger must be a canonical object" }
            return copy
        }
    }
}
