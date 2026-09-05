package decompengine.agent

import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.math.BigInteger

/** A deterministic binding to the immutable parts of one provider-neutral execution request. */
data class AgentExecutionRequestBinding(
    val contractVersion: Int,
    val requestSha256: String,
    val accessPolicySha256: String,
) {
    init {
        require(contractVersion == AGENT_EXECUTION_CONTRACT_VERSION) {
            "execution receipt uses an unsupported request contract"
        }
        require(requestSha256.isReceiptSha256()) { "execution receipt request digest is invalid" }
        require(accessPolicySha256.isReceiptSha256()) { "execution receipt access-policy digest is invalid" }
    }

    companion object {
        fun capture(request: AgentExecutionRequest): AgentExecutionRequestBinding {
            val policySha256 = digestAccessPolicy(request)
            return AgentExecutionRequestBinding(
                contractVersion = request.schemaVersion,
                requestSha256 = RequestBindingDigest().apply {
                    field("contract", request.schemaVersion.toString())
                    field("objective", request.objective)
                    field("workspaceRootsSha256", digestWorkspaceRoots(request))
                    field("contextInputsSha256", digestContextInputs(request))
                    field("accessPolicySha256", policySha256)
                    field("wallClockTimeoutNanos", request.limits.wallClockTimeout.exactNanoseconds())
                    field("idleTimeoutNanos", request.limits.idleTimeout.exactNanoseconds())
                    field("maximumTurns", request.limits.maxTurns.toString())
                    field("maximumToolCalls", request.limits.maxToolCalls.toString())
                    field("maximumOutputBytes", request.limits.maxOutputBytes.toString())
                    field("maximumInputTokens", request.limits.maxInputTokens?.toString())
                    field("maximumOutputTokens", request.limits.maxOutputTokens?.toString())
                    request.sessionContinuation?.let { field("sessionContinuationV1", it.bindingSha256()) }
                }.finish(),
                accessPolicySha256 = policySha256,
            )
        }
    }
}

sealed interface AgentExecutionOutcome {
    class Returned(val result: AgentExecutionResult) : AgentExecutionOutcome
    class Failed(val failure: AgentFailure) : AgentExecutionOutcome
}

/**
 * Marker for immutable, bounded evidence supplied by one provider adapter.
 *
 * Implementations must defensively copy nested collections and must not retain credentials,
 * environment values, raw protocol frames, or other peer-controlled secret-bearing payloads.
 */
interface AgentExecutionProviderEvidence {
    val providerId: String
    val schemaVersion: Int
}

/** The terminal outcome and provider evidence produced by exactly one request invocation. */
class AgentExecutionReceipt(
    val requestBinding: AgentExecutionRequestBinding,
    val outcome: AgentExecutionOutcome,
    val providerEvidence: AgentExecutionProviderEvidence? = null,
    internal val failureCause: Throwable? = null,
) {
    init {
        providerEvidence?.let { evidence ->
            require(evidence.providerId.matches(Regex("[a-z][a-z0-9.-]{0,63}"))) {
                "execution receipt provider id is invalid"
            }
            require(evidence.schemaVersion > 0) { "execution receipt provider schema must be positive" }
        }
        require(outcome is AgentExecutionOutcome.Failed || failureCause == null) {
            "a returned execution receipt cannot retain a failure cause"
        }
    }

    fun requireResult(): AgentExecutionResult = when (val terminal = outcome) {
        is AgentExecutionOutcome.Returned -> terminal.result
        is AgentExecutionOutcome.Failed -> throw AgentExecutionException(
            failure = terminal.failure,
            cause = failureCause,
            receipt = this,
        )
    }
}

/** Compatibility wrapper used by provider-neutral version-1 harness implementations. */
internal inline fun captureAgentExecutionReceipt(
    request: AgentExecutionRequest,
    providerEvidence: () -> AgentExecutionProviderEvidence? = { null },
    execute: () -> AgentExecutionResult,
): AgentExecutionReceipt {
    val binding = AgentExecutionRequestBinding.capture(request)
    return try {
        AgentExecutionReceipt(
            binding,
            AgentExecutionOutcome.Returned(execute()),
            providerEvidence(),
        )
    } catch (failure: AgentExecutionException) {
        failure.receipt?.let { existing ->
            require(existing.requestBinding == binding) {
                "agent failure receipt is bound to a different execution request"
            }
            return existing
        }
        AgentExecutionReceipt(
            binding,
            AgentExecutionOutcome.Failed(failure.failure),
            providerEvidence(),
            failure,
        )
    } catch (failure: Exception) {
        AgentExecutionReceipt(
            binding,
            AgentExecutionOutcome.Failed(
                AgentFailure(
                    kind = if (failure is IllegalArgumentException) {
                        AgentFailureKind.INVALID_REQUEST
                    } else {
                        AgentFailureKind.INTERNAL
                    },
                    message = if (failure is IllegalArgumentException) {
                        "agent execution request was rejected"
                    } else {
                        "agent harness failed without a typed execution outcome"
                    },
                    details = mapOf("exception" to failure.javaClass.name),
                ),
            ),
            providerEvidence(),
            failure,
        )
    }
}

private fun digestWorkspaceRoots(request: AgentExecutionRequest): String = RequestBindingDigest().apply {
    field("count", request.workspaceRoots.size.toString())
    request.workspaceRoots.forEachIndexed { index, root ->
        field("root[$index].id", root.id)
        field("root[$index].path", root.path.toString())
    }
}.finish()

private fun digestContextInputs(request: AgentExecutionRequest): String = RequestBindingDigest().apply {
    field("count", request.contextInputs.size.toString())
    request.contextInputs.forEachIndexed { index, context ->
        field("context[$index].id", context.id)
        field("context[$index].mediaType", context.mediaType)
        field("context[$index].description", context.description)
        field("context[$index].content", context.content)
    }
}.finish()

private fun digestAccessPolicy(request: AgentExecutionRequest): String = RequestBindingDigest().apply {
    val operations = request.accessPolicy.allowedOperations.map(AgentOperation::name).sorted()
    field("allowedOperationCount", operations.size.toString())
    operations.forEachIndexed { index, operation -> field("allowedOperation[$index]", operation) }
    val rules = request.accessPolicy.pathRules.sortedWith(
        compareBy(
            { it.path.rootId },
            { it.path.relativePath },
            { it.recursive },
            { it.operations.map(AgentOperation::name).sorted().joinToString(",") },
        ),
    )
    field("pathRuleCount", rules.size.toString())
    rules.forEachIndexed { index, rule ->
        field("pathRule[$index].rootId", rule.path.rootId)
        field("pathRule[$index].relativePath", rule.path.relativePath)
        field("pathRule[$index].recursive", rule.recursive.toString())
        val ruleOperations = rule.operations.map(AgentOperation::name).sorted()
        field("pathRule[$index].operationCount", ruleOperations.size.toString())
        ruleOperations.forEachIndexed { operationIndex, operation ->
            field("pathRule[$index].operation[$operationIndex]", operation)
        }
    }
}.finish()

private class RequestBindingDigest {
    private val digest = MessageDigest.getInstance("SHA-256")

    fun field(name: String, value: String?) {
        component(receiptCommitmentBytes(name))
        if (value == null) {
            digest.update(0.toByte())
        } else {
            digest.update(1.toByte())
            component(receiptCommitmentBytes(value))
        }
    }

    fun finish(): String = digest.digest().joinToString("") { byte -> "%02x".format(byte) }

    private fun component(bytes: ByteArray) {
        digest.update(ByteBuffer.allocate(Long.SIZE_BYTES).putLong(bytes.size.toLong()).array())
        digest.update(bytes)
    }
}

/**
 * Valid text retains the archive's exact UTF-8 commitment. Malformed JVM strings use a 0xff
 * domain marker (impossible in valid UTF-8) followed by their raw UTF-16BE code units, preserving
 * injectivity without making malformed text archive-serializable.
 */
internal fun receiptCommitmentBytes(value: String): ByteArray = try {
    val encoded = StandardCharsets.UTF_8.newEncoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .encode(CharBuffer.wrap(value))
    ByteArray(encoded.remaining()).also(encoded::get)
} catch (_: CharacterCodingException) {
    ByteArray(Math.addExact(1, Math.multiplyExact(value.length, Char.SIZE_BYTES))).also { encoded ->
        encoded[0] = 0xff.toByte()
        value.forEachIndexed { index, codeUnit ->
            encoded[1 + index * 2] = (codeUnit.code ushr 8).toByte()
            encoded[2 + index * 2] = codeUnit.code.toByte()
        }
    }
}

private fun String.isReceiptSha256(): Boolean =
    length == 64 && all { character -> character in '0'..'9' || character in 'a'..'f' }

private fun java.time.Duration.exactNanoseconds(): String =
    BigInteger.valueOf(seconds)
        .multiply(BigInteger.valueOf(1_000_000_000L))
        .add(BigInteger.valueOf(nano.toLong()))
        .toString()
