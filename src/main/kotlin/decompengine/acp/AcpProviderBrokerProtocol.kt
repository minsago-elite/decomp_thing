package decompengine.acp

import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Duration

internal enum class AcpProviderProtocolVersion(val wireCode: Int) { V1(1), V2(2) }

internal enum class AcpProviderFrameTag(val wireCode: Int) {
    ACP_BYTES(1),
    PROVIDER_REQUEST(2),
    PROVIDER_RESPONSE_HEADERS(3),
    PROVIDER_RESPONSE_CHUNK(4),
    PROVIDER_RESPONSE_END(5),
    PROVIDER_CANCEL(6),
    CHANNEL_OPEN(7),
    CHANNEL_CLEANUP(8),
}

internal enum class AcpProviderFrameDirection {
    HOST_TO_GUARDIAN,
    GUARDIAN_TO_HOST,
}

internal enum class AcpProviderTerminalKind(val wireCode: Int) {
    COMPLETED(0), AUTHENTICATION(1), AUTHORIZATION(2), RESOURCE_EXHAUSTED(3), TIMEOUT(4), CANCELLED(5),
    UNSUPPORTED_OPERATION(6), UNSUPPORTED_MODEL(7), MALFORMED_REQUEST(8), MALFORMED_RESPONSE(9),
    TRANSPORT(10), REVOKED(11), SECRET_EXPOSURE(12),
}

/** No raw provider/ACP bytes, invocation capability, or credentials appear in diagnostics. */
internal class AcpProviderProtocolException(message: String) : IOException(message)

internal class AcpProviderFrame(
    val tag: AcpProviderFrameTag,
    val requestSequence: Long,
    payload: ByteArray,
    val version: AcpProviderProtocolVersion = AcpProviderProtocolVersion.V1,
) {
    private val content: ByteArray
    val payload: ByteArray get() = content.copyOf()
    val payloadSize: Int get() = content.size

    init {
        requireProviderSequence(tag, requestSequence)
        if (payload.size > MAXIMUM_PROVIDER_FRAME_PAYLOAD_BYTES) {
            throw AcpProviderProtocolException("provider frame payload exceeds the absolute bound")
        }
        content = payload.copyOf()
    }

    internal fun writePayload(output: OutputStream) = output.write(content)
    internal fun consumeCleanupPayload(authenticator: AcpProviderCleanupAuthenticator, cleanupTimeoutMillis: Long): AcpProviderCleanupReceipt {
        if (version != AcpProviderProtocolVersion.V2 || tag != AcpProviderFrameTag.CHANNEL_CLEANUP) {
            invalid("provider frame is not a v2 cleanup receipt")
        }
        return AcpProviderBrokerProtocol.decodeCleanupReceipt(content, authenticator, cleanupTimeoutMillis)
    }

    override fun toString(): String = "AcpProviderFrame(tag=$tag, requestSequence=$requestSequence, payloadBytes=${content.size})"
}

internal class AcpProviderRequestPayload private constructor(capability: ByteArray, body: ByteArray) {
    private val capabilityContent = capability.copyOf()
    private val bodyContent = body.copyOf()
    val capability: ByteArray get() = capabilityContent.copyOf()
    val body: ByteArray get() = bodyContent.copyOf()

    override fun toString(): String = "AcpProviderRequestPayload(capability=<redacted>, bodyBytes=${bodyContent.size})"

    companion object {
        internal fun decoded(capability: ByteArray, body: ByteArray): AcpProviderRequestPayload =
            AcpProviderRequestPayload(capability, body)
    }
}

/** Startup capability material is carried once on the private stream and never in diagnostics. */
internal class AcpProviderChannelSetup private constructor(
    capability: ByteArray,
    policySha256: ByteArray,
    invocationBindingSha256: ByteArray,
    limits: IntArray,
    times: LongArray,
) {
    private val capabilityContent = capability.copyOf()
    private val policyDigest = policySha256.copyOf()
    private val invocationDigest = invocationBindingSha256.copyOf()
    private val integerLimits = limits.copyOf()
    private val timeLimits = times.copyOf()
    val capability: ByteArray get() = capabilityContent.copyOf()
    val policySha256: ByteArray get() = policyDigest.copyOf()
    val invocationBindingSha256: ByteArray get() = invocationDigest.copyOf()
    val maximumRequestBytes: Int get() = integerLimits[0]
    val maximumResponseBytes: Int get() = integerLimits[1]
    val maximumHeaderBytes: Int get() = integerLimits[2]
    val maximumHeaderFields: Int get() = integerLimits[3]
    val maximumChunkBytes: Int get() = integerLimits[4]
    val maximumQueuedChunks: Int get() = integerLimits[5]
    val maximumRequests: Int get() = integerLimits[6]
    val maximumOutputTokens: Int get() = integerLimits[7]
    val remainingOverallMillis: Long get() = timeLimits[0]
    val idleTimeoutMillis: Long get() = timeLimits[1]
    val cleanupTimeoutMillis: Long get() = timeLimits[2]

    internal fun eraseIdentity() { capabilityContent.fill(0); policyDigest.fill(0); invocationDigest.fill(0) }

    internal fun requireMatches(bounds: AcpProviderTransportBounds) {
        if (!integerLimits.contentEquals(providerIntegerLimits(bounds)) ||
            idleTimeoutMillis != bounds.idleTimeout.toMillis() || cleanupTimeoutMillis != bounds.cleanupTimeout.toMillis() ||
            remainingOverallMillis > bounds.overallTimeout.toMillis()) {
            invalid("provider channel setup differs from the approved limits")
        }
    }

    internal fun requireMatches(policy: AcpProviderTransportPolicy.Enabled) {
        requireMatches(policy.bounds)
        if (!MessageDigest.isEqual(policyDigest, providerDigestBytes(policy.descriptorSha256))) {
            invalid("provider channel setup differs from the approved policy")
        }
    }

    override fun toString(): String = "AcpProviderChannelSetup(capability=<redacted>, binding=<redacted>, limits=<bounded>)"

    companion object {
        internal fun decoded(capability: ByteArray, policySha256: ByteArray, bindingSha256: ByteArray,
            limits: IntArray, times: LongArray): AcpProviderChannelSetup =
            AcpProviderChannelSetup(capability, policySha256, bindingSha256, limits, times)
    }
}

internal class AcpProviderResponseHeaders private constructor(val status: Int, val contentType: String?) {
    companion object {
        internal fun decoded(status: Int, contentType: String?): AcpProviderResponseHeaders =
            AcpProviderResponseHeaders(status, contentType)
    }
}

/** The callback receives fixed, validated metadata before any payload byte is read. */
internal data class AcpProviderFrameHeader(
    val version: AcpProviderProtocolVersion,
    val tag: AcpProviderFrameTag,
    val requestSequence: Long,
    val payloadBytes: Int,
)

internal enum class AcpProviderCleanupCause(val wireCode: Int) {
    NORMAL(0), HOST_REVOKED(1), GUARDIAN_SIGNAL(2), DEADLINE(3), PROTOCOL_FAILURE(4), CHILD_STDERR(5),
    LAUNCH_FAILURE(6), UNKNOWN(255),
}

/** Only a domain-separated secret-bound digest survives host-side capability revocation. */
internal class AcpProviderCleanupAuthenticator private constructor(private val digest: ByteArray) {
    internal fun authenticates(payload: ByteArray): Boolean {
        val actual = cleanupCommitment(payload)
        return try { MessageDigest.isEqual(digest, actual) } finally { actual.fill(0) }
    }
    override fun toString(): String = "AcpProviderCleanupAuthenticator(<redacted>)"

    companion object {
        internal fun fromSetup(setup: ByteArray): AcpProviderCleanupAuthenticator {
            val decoded = AcpProviderBrokerProtocol.decodeChannelSetupPayload(setup, version = AcpProviderProtocolVersion.V2)
            return try { AcpProviderCleanupAuthenticator(cleanupCommitment(setup)) } finally { decoded.eraseIdentity() }
        }
    }
}

/** Bounded immutable facts only; no capability, policy bytes or invocation bytes survive decode. */
internal data class AcpProviderCleanupReceipt internal constructor(
    val cause: AcpProviderCleanupCause,
    val childExitKind: AcpProviderChildExitKind,
    val rawWaitStatus: Long,
    val childExitCode: Int?,
    val childSignal: Int?,
    val statusPresent: Boolean,
    val finalEchild: Boolean,
    val sigtermSent: Boolean,
    val sigkillSent: Boolean,
    val descriptorsClosed: Boolean,
    val stateRootRemoved: Boolean,
    val descendantsZero: Boolean,
    val cleanupDeadlineExpired: Boolean,
    val remainingDescendants: Int?,
    val closedDescriptorMask: Int,
    val cleanupElapsedMillis: Long,
) {
    val nativeCleanupVerified: Boolean get() = statusPresent && finalEchild && descendantsZero &&
        remainingDescendants == 0 && descriptorsClosed && closedDescriptorMask == 0x3f && stateRootRemoved &&
        !cleanupDeadlineExpired && cause != AcpProviderCleanupCause.UNKNOWN && cause != AcpProviderCleanupCause.DEADLINE
}

// This exact literal, including the terminating NUL, is part of the v2 ABI.
private val CLEANUP_COMMITMENT_DOMAIN = "acpp-v2-cleanup\u0000".toByteArray(StandardCharsets.US_ASCII)

private fun cleanupCommitment(payload: ByteArray): ByteArray {
    if (payload.size < 96) invalid("provider cleanup identity is truncated")
    return MessageDigest.getInstance("SHA-256").run {
        update(CLEANUP_COMMITMENT_DOMAIN)
        update(payload, 0, 96)
        digest()
    }
}

/**
 * Exact v1 grammar, network byte order:
 * magic[4]="ACPP", version:u8=1, tag:u8=1..7, sequence:u64, payloadLength:u32, payload[payloadLength].
 * There are no reserved fields, extensions, or trailing bytes within a frame. Sequence 0 is only
 * ACP_BYTES and CHANNEL_OPEN; provider sequences are 1..Long.MAX_VALUE, with the unsigned high half rejected.
 * REQUEST is capability[32] followed by one nonempty bounded request body. END is exactly one
 * closed terminal-code byte. CANCEL is empty. Limits and ordering are validated separately before
 * provider dispatch. CHANNEL_OPEN is exactly 152 bytes: capability[32], policySha256[32],
 * invocationBindingSha256[32], eight positive u32 limits in declared setup order, then three
 * positive u64 milliseconds (remainingOverall, idle, cleanup), with the unsigned high half rejected.
 * A caller owns stream deadlines and cleanup; this codec does not start tasks.
 */
internal object AcpProviderBrokerProtocol {
    const val HEADER_BYTES: Int = 18
    const val VERSION: Int = 1
    const val CHANNEL_SETUP_BYTES: Int = 152
    const val CHANNEL_SETUP_V2_BYTES: Int = 156
    const val TERMINAL_CLEANUP_RECEIPT_FEATURE: Int = 1
    const val CHANNEL_CLEANUP_BYTES: Int = 116
    private val MAGIC = byteArrayOf(0x41, 0x43, 0x50, 0x50)

    fun readFrame(input: InputStream, maximumPayloadBytes: Int, direction: AcpProviderFrameDirection,
        version: AcpProviderProtocolVersion = AcpProviderProtocolVersion.V1,
        validatedHeader: (AcpProviderFrameHeader) -> Unit = {},
    ): AcpProviderFrame? {
        requireFrameLimit(maximumPayloadBytes)
        val first = input.read()
        if (first == -1) return null
        val header = ByteArray(HEADER_BYTES)
        header[0] = first.toByte()
        readExactly(input, header, 1, HEADER_BYTES - 1)
        if (!header.copyOfRange(0, 4).contentEquals(MAGIC)) {
            throw AcpProviderProtocolException("provider frame magic is invalid")
        }
        if ((header[4].toInt() and 0xff) != version.wireCode) {
            throw AcpProviderProtocolException("provider frame version is unsupported")
        }
        val tag = AcpProviderFrameTag.entries.singleOrNull { it.wireCode == (header[5].toInt() and 0xff) }
            ?: throw AcpProviderProtocolException("provider frame tag is unsupported")
        requireFrameVersion(tag, version)
        requireFrameDirection(tag, direction)
        val fields = ByteBuffer.wrap(header).order(ByteOrder.BIG_ENDIAN)
        val sequence = fields.getLong(6)
        requireProviderSequence(tag, sequence)
        val payloadLength = fields.getInt(14).toLong() and 0xffff_ffffL
        if (payloadLength > maximumPayloadBytes.toLong()) {
            throw AcpProviderProtocolException("provider frame payload exceeds the supplied bound")
        }
        requireTagPayloadLength(tag, payloadLength, version)
        validatedHeader(AcpProviderFrameHeader(version, tag, sequence, payloadLength.toInt()))
        // Allocation follows the complete fixed header, unsigned conversion, and both cap checks.
        val payload = ByteArray(payloadLength.toInt())
        try {
            readExactly(input, payload, 0, payload.size)
            requireTagPayload(tag, payload, version)
            return AcpProviderFrame(tag, sequence, payload, version)
        } finally {
            if (tag == AcpProviderFrameTag.CHANNEL_CLEANUP) payload.fill(0)
        }
    }

    fun writeFrame(output: OutputStream, frame: AcpProviderFrame, maximumPayloadBytes: Int, direction: AcpProviderFrameDirection) {
        requireFrameLimit(maximumPayloadBytes)
        requireFrameVersion(frame.tag, frame.version)
        requireFrameDirection(frame.tag, direction)
        if (frame.payloadSize > maximumPayloadBytes) {
            throw AcpProviderProtocolException("provider frame payload exceeds the supplied bound")
        }
        requireTagPayloadLength(frame.tag, frame.payloadSize.toLong(), frame.version)
        requireTagPayload(frame.tag, frame.payload, frame.version)
        val header = ByteBuffer.allocate(HEADER_BYTES).order(ByteOrder.BIG_ENDIAN)
            .put(MAGIC).put(frame.version.wireCode.toByte()).put(frame.tag.wireCode.toByte())
            .putLong(frame.requestSequence).putInt(frame.payloadSize).array()
        synchronized(output) {
            output.write(header)
            frame.writePayload(output)
        }
    }

    /** Consumes the identity bytes even on authentication or field-validation failure. */
    fun decodeCleanupReceipt(
        payload: ByteArray,
        authenticator: AcpProviderCleanupAuthenticator,
        cleanupTimeoutMillis: Long,
    ): AcpProviderCleanupReceipt {
        val authenticated = try {
            if (cleanupTimeoutMillis !in 1..Duration.ofMinutes(30).toMillis()) invalid("provider cleanup timeout is invalid")
            if (payload.size != CHANNEL_CLEANUP_BYTES) invalid("provider cleanup receipt has an invalid length")
            authenticator.authenticates(payload)
        } finally {
            payload.fill(0, 0, minOf(96, payload.size))
        }
        if (!authenticated) invalid("provider cleanup receipt identity is invalid")
        val input = ByteBuffer.wrap(payload).order(ByteOrder.BIG_ENDIAN)
        if ((input.get(96).toInt() and 0xff) != 1) invalid("provider cleanup receipt schema is unsupported")
        val cause = AcpProviderCleanupCause.entries.singleOrNull { it.wireCode == (input.get(97).toInt() and 0xff) }
            ?: invalid("provider cleanup receipt cause is unsupported")
        val outcome = input.get(98).toInt() and 0xff
        val flags = input.get(99).toInt() and 0xff
        fun flag(bit: Int): Boolean = flags and (1 shl bit) != 0
        val statusPresent = flag(0)
        val rawStatus = input.getInt(100).toLong() and 0xffff_ffffL
        val descendants = input.getInt(104).toLong() and 0xffff_ffffL
        val descriptors = input.getInt(108).toLong() and 0xffff_ffffL
        val elapsed = input.getInt(112).toLong() and 0xffff_ffffL
        val childKind: AcpProviderChildExitKind
        var exitCode: Int? = null
        var signal: Int? = null
        if (!statusPresent) {
            if (rawStatus != 0L || outcome != 0) invalid("provider cleanup receipt invents an unobserved child status")
            childKind = AcpProviderChildExitKind.UNOBSERVED
        } else {
            if (rawStatus > 0xffffL) invalid("provider cleanup receipt wait status is unsupported")
            val low = rawStatus.toInt() and 0xff
            if (low == 0) {
                childKind = AcpProviderChildExitKind.EXITED
                exitCode = (rawStatus.toInt() ushr 8) and 0xff
                if (outcome != 1) invalid("provider cleanup receipt outcome differs from the wait status")
            } else {
                val observedSignal = low and 0x7f
                if (rawStatus > 0xffL || observedSignal !in 1..64) {
                    invalid("provider cleanup receipt is not a terminal child wait status")
                }
                signal = observedSignal
                childKind = when (observedSignal) {
                    15 -> AcpProviderChildExitKind.SIGTERM
                    9 -> AcpProviderChildExitKind.SIGKILL
                    else -> AcpProviderChildExitKind.OTHER_SIGNAL
                }
                val expected = when (childKind) {
                    AcpProviderChildExitKind.SIGTERM -> 2
                    AcpProviderChildExitKind.SIGKILL -> 3
                    else -> 4
                }
                if (outcome != expected) invalid("provider cleanup receipt outcome differs from the wait status")
            }
        }
        if (descendants != 0xffff_ffffL && descendants !in 0..32) invalid("provider cleanup descendant count is unsupported")
        if (flag(6) != (descendants == 0L)) invalid("provider cleanup descendant flag differs from its count")
        if (flag(1) && descendants != 0L) invalid("provider cleanup ECHILD differs from its descendant count")
        if (descriptors and 0xffff_ffc0L != 0L || flag(4) != (descriptors == 0x3fL)) {
            invalid("provider cleanup descriptor flag differs from its mask")
        }
        if (flag(3) && !flag(2)) invalid("provider cleanup escalation omits its TERM attempt")
        if (elapsed > cleanupTimeoutMillis + 1 || flag(7) != (elapsed == cleanupTimeoutMillis + 1)) {
            invalid("provider cleanup elapsed time differs from its deadline flag")
        }
        if (cause == AcpProviderCleanupCause.NORMAL &&
            (!statusPresent || flag(2) || flag(3))) {
            invalid("provider normal cleanup differs from its child outcome")
        }
        return AcpProviderCleanupReceipt(cause, childKind, rawStatus, exitCode, signal, statusPresent, flag(1),
            flag(2), flag(3), flag(4), flag(5), flag(6), flag(7),
            if (descendants == 0xffff_ffffL) null else descendants.toInt(), descriptors.toInt(), elapsed)
    }

    fun requestPayload(capability: ByteArray, body: ByteArray, bounds: AcpProviderTransportBounds): ByteArray {
        if (capability.size != PROVIDER_INVOCATION_CAPABILITY_BYTES) {
            throw AcpProviderProtocolException("provider invocation capability has an invalid length")
        }
        if (body.isEmpty() || body.size > bounds.maximumRequestBytes) {
            throw AcpProviderProtocolException("provider request body is empty or exceeds the bound")
        }
        return ByteArray(PROVIDER_INVOCATION_CAPABILITY_BYTES + body.size).also {
            capability.copyInto(it)
            body.copyInto(it, PROVIDER_INVOCATION_CAPABILITY_BYTES)
        }
    }

    fun decodeRequestPayload(payload: ByteArray, bounds: AcpProviderTransportBounds): AcpProviderRequestPayload {
        if (payload.size <= PROVIDER_INVOCATION_CAPABILITY_BYTES ||
            payload.size - PROVIDER_INVOCATION_CAPABILITY_BYTES > bounds.maximumRequestBytes) {
            throw AcpProviderProtocolException("provider request payload is empty or exceeds the bound")
        }
        return AcpProviderRequestPayload.decoded(
            payload.copyOfRange(0, PROVIDER_INVOCATION_CAPABILITY_BYTES),
            payload.copyOfRange(PROVIDER_INVOCATION_CAPABILITY_BYTES, payload.size),
        )
    }

    fun terminalPayload(kind: AcpProviderTerminalKind): ByteArray = byteArrayOf(kind.wireCode.toByte())

    fun decodeTerminalPayload(payload: ByteArray): AcpProviderTerminalKind {
        if (payload.size != 1) throw AcpProviderProtocolException("provider terminal payload has an invalid length")
        return AcpProviderTerminalKind.entries.singleOrNull { it.wireCode == (payload[0].toInt() and 0xff) }
            ?: throw AcpProviderProtocolException("provider terminal code is unsupported")
    }

    fun responseHeadersPayload(status: Int, contentType: String?): ByteArray {
        requireResponseHeaders(status, contentType)
        val bytes = contentType?.toByteArray(StandardCharsets.US_ASCII) ?: ByteArray(0)
        return ByteBuffer.allocate(4 + bytes.size).order(ByteOrder.BIG_ENDIAN)
            .putShort(status.toShort()).putShort(bytes.size.toShort()).put(bytes).array()
    }

    fun decodeResponseHeadersPayload(payload: ByteArray, maximumHeaderBytes: Int): AcpProviderResponseHeaders {
        require(maximumHeaderBytes in 1..64 * 1024) { "provider header bound is invalid" }
        if (payload.size !in 4..maximumHeaderBytes) invalid("provider response header envelope is outside the bound")
        val fields = ByteBuffer.wrap(payload).order(ByteOrder.BIG_ENDIAN)
        val status = fields.short.toInt() and 0xffff
        val length = fields.short.toInt() and 0xffff
        if (length != payload.size - 4) invalid("provider response header envelope has a mismatched length")
        val typeBytes = payload.copyOfRange(4, payload.size)
        if (typeBytes.any { (it.toInt() and 0xff) !in 0x20..0x7e }) {
            invalid("provider content type is not canonical ASCII")
        }
        val type = if (typeBytes.isEmpty()) null else String(typeBytes, StandardCharsets.US_ASCII)
        requireResponseHeaders(status, type)
        return AcpProviderResponseHeaders.decoded(status, type)
    }

    fun channelSetupPayload(
        capability: ByteArray,
        policy: AcpProviderTransportPolicy.Enabled,
        invocationBindingSha256: ByteArray,
        remainingOverallMillis: Long,
        version: AcpProviderProtocolVersion = AcpProviderProtocolVersion.V1,
    ): ByteArray {
        if (capability.size != PROVIDER_INVOCATION_CAPABILITY_BYTES || invocationBindingSha256.size != 32) {
            invalid("provider channel setup capability or binding has an invalid length")
        }
        if (remainingOverallMillis !in 1..policy.bounds.overallTimeout.toMillis()) {
            invalid("provider channel remaining timeout is outside the approved bound")
        }
        val output = ByteBuffer.allocate(if (version == AcpProviderProtocolVersion.V1) CHANNEL_SETUP_BYTES else CHANNEL_SETUP_V2_BYTES).order(ByteOrder.BIG_ENDIAN)
            .put(capability).put(providerDigestBytes(policy.descriptorSha256)).put(invocationBindingSha256)
        providerIntegerLimits(policy.bounds).forEach { output.putInt(it) }
        output.putLong(remainingOverallMillis)
            .putLong(policy.bounds.idleTimeout.toMillis()).putLong(policy.bounds.cleanupTimeout.toMillis())
        if (version == AcpProviderProtocolVersion.V2) output.putInt(TERMINAL_CLEANUP_RECEIPT_FEATURE)
        return output.array()
    }

    fun decodeChannelSetupPayload(
        payload: ByteArray,
        expectedPolicy: AcpProviderTransportPolicy.Enabled? = null,
        version: AcpProviderProtocolVersion = AcpProviderProtocolVersion.V1,
    ): AcpProviderChannelSetup {
        val expectedSize = if (version == AcpProviderProtocolVersion.V1) CHANNEL_SETUP_BYTES else CHANNEL_SETUP_V2_BYTES
        if (payload.size != expectedSize) invalid("provider channel setup has an invalid length")
        val input = ByteBuffer.wrap(payload).order(ByteOrder.BIG_ENDIAN)
        val capability = ByteArray(32).also { input.get(it) }
        val policyDigest = ByteArray(32).also { input.get(it) }
        val bindingDigest = ByteArray(32).also { input.get(it) }
        try {
            val limits = IntArray(8) { input.int }
            val times = LongArray(3) { input.long }
            if (version == AcpProviderProtocolVersion.V2 && input.int != TERMINAL_CLEANUP_RECEIPT_FEATURE) {
                invalid("provider channel setup required features are unsupported")
            }
            if (limits.any { it <= 0 } || times.any { it !in 1..Duration.ofMinutes(30).toMillis() }) {
                invalid("provider channel setup contains unsupported unsigned limits")
            }
            try {
                // This constructs only a validation value with the static duration ceiling. The actual
                // remaining invocation deadline stays explicit in the setup and is never inferred.
                AcpProviderTransportBounds(limits[0], limits[1], limits[2], limits[3], limits[4], limits[5], limits[6], limits[7],
                    Duration.ofMinutes(30), Duration.ofMillis(times[1]), Duration.ofMillis(times[2]))
            } catch (_: IllegalArgumentException) {
                invalid("provider channel setup exceeds the static bounds")
            }
            val decoded = AcpProviderChannelSetup.decoded(capability, policyDigest, bindingDigest, limits, times)
            try {
                expectedPolicy?.let(decoded::requireMatches)
                return decoded
            } catch (failure: Exception) {
                decoded.eraseIdentity()
                throw failure
            }
        } finally {
            capability.fill(0); policyDigest.fill(0); bindingDigest.fill(0)
        }
    }
}

/** One host invocation owner validates identity and combined inbound/outbound frame order. */
internal class AcpProviderFrameOrder(
    private val policy: AcpProviderTransportPolicy.Enabled,
    expectedInvocationBindingSha256: ByteArray,
    expectedCapability: ByteArray,
    private val version: AcpProviderProtocolVersion = AcpProviderProtocolVersion.V1,
) {
    private val bounds = policy.bounds
    private val invocationDigest = providerIdentitySnapshot(expectedInvocationBindingSha256)
    private val invocationCapability = providerIdentitySnapshot(expectedCapability)
    private enum class Stage { AWAITING_HEADERS, STREAMING, REJECTED, CANCELLED }
    private var lastSequence = 0L
    private var activeSequence: Long? = null
    private var stage: Stage? = null
    private var invocationResponseBytes = 0L
    private var failed = false
    private var finished = false
    private var channelOpened = false
    private var cleanupBegun = false
    private var cleanupReceived = false

    @Synchronized
    fun accept(frame: AcpProviderFrame) {
        if (finished || (failed && !cleanupBegun)) invalid("provider frame owner has already failed or finished")
        try {
            if (frame.version != version) invalid("provider channel version changed")
            if (cleanupBegun && frame.tag != AcpProviderFrameTag.CHANNEL_CLEANUP) {
                invalid("provider frame follows cleanup revocation")
            }
            if (!channelOpened && frame.tag != AcpProviderFrameTag.CHANNEL_OPEN) invalid("provider channel has not been opened")
            when (frame.tag) {
                AcpProviderFrameTag.CHANNEL_CLEANUP -> {
                    if (version != AcpProviderProtocolVersion.V2 || !cleanupBegun || cleanupReceived || frame.payloadSize != AcpProviderBrokerProtocol.CHANNEL_CLEANUP_BYTES) {
                        invalid("provider cleanup receipt is repeated or out of order")
                    }
                    cleanupReceived = true
                    finished = true
                }
                AcpProviderFrameTag.CHANNEL_OPEN -> {
                    if (channelOpened) invalid("provider channel setup is repeated")
                    val setup = AcpProviderBrokerProtocol.decodeChannelSetupPayload(frame.payload, policy, version)
                    try {
                        if (!MessageDigest.isEqual(setup.invocationBindingSha256, invocationDigest) ||
                            !MessageDigest.isEqual(setup.capability, invocationCapability)) {
                            invalid("provider channel setup differs from the expected invocation")
                        }
                        channelOpened = true
                    } finally { setup.eraseIdentity() }
                }
                AcpProviderFrameTag.ACP_BYTES -> {
                    if (frame.payloadSize !in 1..bounds.maximumChunkBytes) invalid("ACP byte chunk is empty or exceeds the bound")
                }
                AcpProviderFrameTag.PROVIDER_REQUEST -> {
                    if (activeSequence != null) invalid("provider request overlaps an active request")
                    if (lastSequence >= bounds.maximumRequests || frame.requestSequence != lastSequence + 1) {
                        invalid("provider request sequence is replayed, out of order, or exceeds the invocation bound")
                    }
                    val request = AcpProviderBrokerProtocol.decodeRequestPayload(frame.payload, bounds)
                    if (!MessageDigest.isEqual(request.capability, invocationCapability)) {
                        invalid("provider opening capability differs from the admitted invocation")
                    }
                    activeSequence = frame.requestSequence
                    lastSequence = frame.requestSequence
                    stage = Stage.AWAITING_HEADERS
                }
                AcpProviderFrameTag.PROVIDER_RESPONSE_HEADERS -> {
                    requireActive(frame)
                    if (stage != Stage.AWAITING_HEADERS) invalid("provider response headers are repeated or out of order")
                    if (frame.payloadSize !in 1..bounds.maximumHeaderBytes) invalid("provider response headers are empty or exceed the bound")
                    val headers = AcpProviderBrokerProtocol.decodeResponseHeadersPayload(frame.payload, bounds.maximumHeaderBytes)
                    stage = if (headers.status == 200) Stage.STREAMING else Stage.REJECTED
                }
                AcpProviderFrameTag.PROVIDER_RESPONSE_CHUNK -> {
                    requireActive(frame)
                    if (stage != Stage.STREAMING) invalid("provider response chunk precedes headers or follows cancellation")
                    if (frame.payloadSize !in 1..bounds.maximumChunkBytes) invalid("provider response chunk is empty or exceeds the bound")
                    val nextBytes = invocationResponseBytes + frame.payloadSize
                    if (nextBytes > bounds.maximumResponseBytes) invalid("provider response exceeds the invocation byte bound")
                    invocationResponseBytes = nextBytes
                }
                AcpProviderFrameTag.PROVIDER_CANCEL -> {
                    requireActive(frame)
                    if (stage == Stage.CANCELLED || frame.payloadSize != 0) invalid("provider cancellation is repeated or has a payload")
                    stage = Stage.CANCELLED
                }
                AcpProviderFrameTag.PROVIDER_RESPONSE_END -> {
                    requireActive(frame)
                    val kind = AcpProviderBrokerProtocol.decodeTerminalPayload(frame.payload)
                    if (kind == AcpProviderTerminalKind.COMPLETED && stage != Stage.STREAMING) {
                        invalid("provider completion precedes response headers or follows cancellation")
                    }
                    if (stage == Stage.CANCELLED && kind != AcpProviderTerminalKind.CANCELLED && kind != AcpProviderTerminalKind.REVOKED) {
                        invalid("provider cancellation has an incompatible terminal code")
                    }
                    activeSequence = null
                    stage = null
                }
            }
        } catch (failure: AcpProviderProtocolException) {
            failed = true
            throw failure
        }
    }

    /** Revocation remains available after a protocol failure; it never repairs that failure. */
    @Synchronized
    fun beginCleanup() {
        if (cleanupBegun || finished) invalid("provider cleanup transition is repeated or finished")
        cleanupBegun = true
        activeSequence = null
        stage = null
        invocationCapability.fill(0)
        invocationDigest.fill(0)
    }

    @Synchronized
    fun hasFailed(): Boolean = failed

    @Synchronized
    fun hasActiveRequest(): Boolean = activeSequence != null

    @Synchronized
    fun finish() {
        if (version == AcpProviderProtocolVersion.V2) {
            if (failed || !cleanupReceived) invalid("provider v2 stream lacks a valid terminal cleanup transition")
            return
        }
        if (failed || finished) invalid("provider frame owner has already failed or finished")
        if (activeSequence != null) {
            failed = true
            invalid("provider stream ended with an active request")
        }
        if (!channelOpened) {
            failed = true
            invalid("provider stream ended before channel setup")
        }
        finished = true
    }

    private fun requireActive(frame: AcpProviderFrame) {
        if (activeSequence != frame.requestSequence) invalid("provider frame has an unknown or terminal request sequence")
    }
}

private fun requireFrameLimit(maximumPayloadBytes: Int) {
    require(maximumPayloadBytes in 1..MAXIMUM_PROVIDER_FRAME_PAYLOAD_BYTES) { "provider frame bound is invalid" }
}

private fun requireFrameVersion(tag: AcpProviderFrameTag, version: AcpProviderProtocolVersion) {
    if (tag == AcpProviderFrameTag.CHANNEL_CLEANUP && version != AcpProviderProtocolVersion.V2) {
        invalid("provider cleanup receipt requires protocol v2")
    }
}

private fun requireFrameDirection(tag: AcpProviderFrameTag, direction: AcpProviderFrameDirection) {
    val allowed = when (direction) {
        AcpProviderFrameDirection.HOST_TO_GUARDIAN -> tag != AcpProviderFrameTag.PROVIDER_REQUEST && tag != AcpProviderFrameTag.CHANNEL_CLEANUP
        AcpProviderFrameDirection.GUARDIAN_TO_HOST -> tag == AcpProviderFrameTag.ACP_BYTES ||
            tag == AcpProviderFrameTag.PROVIDER_REQUEST || tag == AcpProviderFrameTag.PROVIDER_CANCEL || tag == AcpProviderFrameTag.CHANNEL_CLEANUP
    }
    if (!allowed) invalid("provider frame tag is invalid for the channel direction")
}

private fun requireTagPayloadLength(tag: AcpProviderFrameTag, length: Long, version: AcpProviderProtocolVersion) {
    val valid = when (tag) {
        AcpProviderFrameTag.ACP_BYTES -> length in 1..(64 * 1024L)
        AcpProviderFrameTag.PROVIDER_REQUEST -> length >= PROVIDER_INVOCATION_CAPABILITY_BYTES + 1
        AcpProviderFrameTag.PROVIDER_RESPONSE_HEADERS -> length in 4..(64 * 1024L)
        AcpProviderFrameTag.PROVIDER_RESPONSE_CHUNK -> length in 1..(64 * 1024L)
        AcpProviderFrameTag.PROVIDER_RESPONSE_END -> length == 1L
        AcpProviderFrameTag.PROVIDER_CANCEL -> length == 0L
        AcpProviderFrameTag.CHANNEL_OPEN -> length == (if (version == AcpProviderProtocolVersion.V1) AcpProviderBrokerProtocol.CHANNEL_SETUP_BYTES else AcpProviderBrokerProtocol.CHANNEL_SETUP_V2_BYTES).toLong()
        AcpProviderFrameTag.CHANNEL_CLEANUP -> version == AcpProviderProtocolVersion.V2 && length == AcpProviderBrokerProtocol.CHANNEL_CLEANUP_BYTES.toLong()
    }
    if (!valid) invalid("provider frame payload length is invalid for its tag")
}

private fun requireTagPayload(tag: AcpProviderFrameTag, payload: ByteArray, version: AcpProviderProtocolVersion) {
    when (tag) {
        AcpProviderFrameTag.CHANNEL_OPEN -> AcpProviderBrokerProtocol.decodeChannelSetupPayload(payload, version = version).eraseIdentity()
        AcpProviderFrameTag.PROVIDER_RESPONSE_END -> AcpProviderBrokerProtocol.decodeTerminalPayload(payload)
        AcpProviderFrameTag.PROVIDER_RESPONSE_HEADERS -> AcpProviderBrokerProtocol.decodeResponseHeadersPayload(payload, 64 * 1024)
        else -> Unit
    }
}

private fun requireResponseHeaders(status: Int, contentType: String?) {
    if ((status == 200 && contentType == "text/event-stream") || (status in 400..599 && contentType == null)) return
    invalid("provider status or content type is unsupported")
}

private fun requireProviderSequence(tag: AcpProviderFrameTag, sequence: Long) {
    val isChannel = tag == AcpProviderFrameTag.ACP_BYTES || tag == AcpProviderFrameTag.CHANNEL_OPEN || tag == AcpProviderFrameTag.CHANNEL_CLEANUP
    if ((isChannel && sequence != 0L) || (!isChannel && sequence <= 0L)) {
        throw AcpProviderProtocolException("provider frame sequence is outside the supported domain")
    }
}

private fun providerIntegerLimits(bounds: AcpProviderTransportBounds): IntArray = intArrayOf(
    bounds.maximumRequestBytes, bounds.maximumResponseBytes, bounds.maximumHeaderBytes, bounds.maximumHeaderFields,
    bounds.maximumChunkBytes, bounds.maximumQueuedChunks, bounds.maximumRequests, bounds.maximumOutputTokens,
)

private fun providerIdentitySnapshot(identity: ByteArray): ByteArray {
    require(identity.size == 32) { "provider frame owner identity has an invalid length" }
    return identity.copyOf()
}

private fun providerDigestBytes(digest: String): ByteArray {
    if (!digest.matches(Regex("[0-9a-f]{64}"))) invalid("provider policy digest is not canonical")
    return ByteArray(32) { digest.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}

private fun readExactly(input: InputStream, bytes: ByteArray, offset: Int, length: Int) {
    var completed = 0
    while (completed < length) {
        val read = input.read(bytes, offset + completed, length - completed)
        if (read == -1) throw EOFException("provider frame is truncated")
        if (read == 0) throw AcpProviderProtocolException("provider stream made no read progress")
        completed += read
    }
}

private fun invalid(message: String): Nothing = throw AcpProviderProtocolException(message)
