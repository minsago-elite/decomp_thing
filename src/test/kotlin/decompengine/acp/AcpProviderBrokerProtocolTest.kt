package decompengine.acp

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class AcpProviderBrokerProtocolTest {
    private val bounds = AcpProviderTransportBounds(maximumRequestBytes = 128, maximumResponseBytes = 64,
        maximumChunkBytes = 32, maximumRequests = 2)
    private val policy = AcpProviderTransportPolicy.issueApproved(APPROVED_CODEX_CHATGPT_RESPONSES_ENDPOINT,
        "gpt-6", AcpProviderReasoning.MEDIUM, bounds)
    private val capability = ByteArray(32) { (it + 1).toByte() }
    private val binding = ByteArray(32) { (it + 33).toByte() }
    private val host = AcpProviderFrameDirection.HOST_TO_GUARDIAN
    private val guardian = AcpProviderFrameDirection.GUARDIAN_TO_HOST

    @Test
    fun `fixed wire header is big endian and payload snapshots cannot mutate a frame`() {
        val body = byteArrayOf(1, 2, 3)
        val frame = AcpProviderFrame(AcpProviderFrameTag.ACP_BYTES, 0, body)
        body[0] = 9
        frame.payload[1] = 9
        val encoded = encode(frame, host)
        assertContentEquals(byteArrayOf(0x41, 0x43, 0x50, 0x50, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3), encoded.copyOfRange(0, 18))
        val decoded = AcpProviderBrokerProtocol.readFrame(ByteArrayInputStream(encoded), 256, host)!!
        assertEquals(frame.tag, decoded.tag)
        assertEquals(0L, decoded.requestSequence)
        assertContentEquals(byteArrayOf(1, 2, 3), decoded.payload)
        assertFalse(frame.toString().contains("[1, 2, 3]"))
    }

    @Test
    fun `clean EOF differs from truncated header and truncated body`() {
        assertNull(AcpProviderBrokerProtocol.readFrame(ByteArrayInputStream(ByteArray(0)), 256, host))
        val encoded = encode(request(), guardian)
        for (length in 1 until encoded.size) {
            assertFailsWith<EOFException> {
                AcpProviderBrokerProtocol.readFrame(ByteArrayInputStream(encoded.copyOf(length)), 256, guardian)
            }
        }
    }

    @Test
    fun `unknown magic version tag and unsigned sequence are refused`() {
        val valid = encode(request(), guardian)
        listOf(0 to 0, 4 to 2, 5 to 0, 5 to 8, 6 to 0x80).forEach { (index, value) ->
            val bytes = valid.copyOf().also { it[index] = value.toByte() }
            assertFailsWith<AcpProviderProtocolException> {
                AcpProviderBrokerProtocol.readFrame(ByteArrayInputStream(bytes), 256, guardian)
            }
        }
        assertFailsWith<AcpProviderProtocolException> { AcpProviderFrame(AcpProviderFrameTag.ACP_BYTES, 1, byteArrayOf(1)) }
        assertFailsWith<AcpProviderProtocolException> { AcpProviderFrame(AcpProviderFrameTag.PROVIDER_REQUEST, 0, ByteArray(33)) }
    }

    @Test
    fun `oversized unsigned and tag specific lengths fail before payload reads`() {
        val examples = listOf(
            Triple(AcpProviderFrameTag.PROVIDER_REQUEST, 0xffff_ffffL, guardian),
            Triple(AcpProviderFrameTag.PROVIDER_REQUEST, 257L, guardian),
            Triple(AcpProviderFrameTag.PROVIDER_REQUEST, 32L, guardian),
            Triple(AcpProviderFrameTag.PROVIDER_RESPONSE_CHUNK, 65_537L, host),
            Triple(AcpProviderFrameTag.PROVIDER_RESPONSE_HEADERS, 65_537L, host),
            Triple(AcpProviderFrameTag.PROVIDER_RESPONSE_END, 2L, host),
            Triple(AcpProviderFrameTag.PROVIDER_CANCEL, 1L, guardian),
            Triple(AcpProviderFrameTag.CHANNEL_OPEN, 153L, host),
            Triple(AcpProviderFrameTag.ACP_BYTES, 0L, guardian),
            Triple(AcpProviderFrameTag.ACP_BYTES, 65_537L, guardian),
        )
        examples.forEach { (tag, length, direction) ->
            val stream = HeaderOnlyInput(header(tag, length))
            assertFailsWith<AcpProviderProtocolException> {
                AcpProviderBrokerProtocol.readFrame(stream, if (length <= 257) 256 else MAXIMUM_PROVIDER_FRAME_PAYLOAD_BYTES, direction)
            }
            assertEquals(18, stream.consumed)
        }
    }

    @Test
    fun `wrong direction is rejected before payload reading or any output`() {
        val forbidden = listOf(AcpProviderFrameTag.CHANNEL_OPEN, AcpProviderFrameTag.PROVIDER_RESPONSE_HEADERS,
            AcpProviderFrameTag.PROVIDER_RESPONSE_CHUNK, AcpProviderFrameTag.PROVIDER_RESPONSE_END)
        forbidden.forEach { tag ->
            val stream = HeaderOnlyInput(header(tag, 1))
            assertFailsWith<AcpProviderProtocolException> { AcpProviderBrokerProtocol.readFrame(stream, 256, guardian) }
            assertEquals(18, stream.consumed)
            val output = ByteArrayOutputStream()
            assertFailsWith<AcpProviderProtocolException> {
                AcpProviderBrokerProtocol.writeFrame(output, AcpProviderFrame(tag, if (tag == AcpProviderFrameTag.CHANNEL_OPEN) 0 else 1,
                    byteArrayOf(0)), 256, guardian)
            }
            assertEquals(0, output.size())
        }
        assertFailsWith<AcpProviderProtocolException> { encode(request(), host) }
    }

    @Test
    fun `request opening binds exactly one capability and one bounded immutable body`() {
        val body = byteArrayOf(10, 20)
        val payload = AcpProviderBrokerProtocol.requestPayload(capability, body, bounds)
        val decoded = AcpProviderBrokerProtocol.decodeRequestPayload(payload, bounds)
        payload.fill(0)
        body.fill(0)
        decoded.capability.fill(0)
        decoded.body.fill(0)
        assertContentEquals(capability, decoded.capability)
        assertContentEquals(byteArrayOf(10, 20), decoded.body)
        assertTrue(decoded.toString().contains("<redacted>"))
        listOf(ByteArray(31), ByteArray(33)).forEach { token ->
            assertFailsWith<AcpProviderProtocolException> { AcpProviderBrokerProtocol.requestPayload(token, byteArrayOf(1), bounds) }
        }
        listOf(ByteArray(0), ByteArray(bounds.maximumRequestBytes + 1)).forEach { bytes ->
            assertFailsWith<AcpProviderProtocolException> { AcpProviderBrokerProtocol.requestPayload(capability, bytes, bounds) }
        }
        listOf(ByteArray(32), ByteArray(32 + bounds.maximumRequestBytes + 1)).forEach { bytes ->
            assertFailsWith<AcpProviderProtocolException> { AcpProviderBrokerProtocol.decodeRequestPayload(bytes, bounds) }
        }
    }

    @Test
    fun `channel setup exact grammar binds policy limits and invocation digest defensively`() {
        val payload = AcpProviderBrokerProtocol.channelSetupPayload(capability, policy, binding, 60_000)
        assertEquals(152, payload.size)
        val setup = AcpProviderBrokerProtocol.decodeChannelSetupPayload(payload, policy)
        assertEquals(bounds.maximumRequestBytes, setup.maximumRequestBytes)
        assertEquals(bounds.maximumResponseBytes, setup.maximumResponseBytes)
        assertEquals(bounds.maximumRequests, setup.maximumRequests)
        assertEquals(60_000L, setup.remainingOverallMillis)
        assertEquals(bounds.idleTimeout.toMillis(), setup.idleTimeoutMillis)
        assertEquals(bounds.cleanupTimeout.toMillis(), setup.cleanupTimeoutMillis)
        payload.fill(0)
        setup.capability.fill(0)
        setup.policySha256.fill(0)
        setup.invocationBindingSha256.fill(0)
        assertContentEquals(capability, setup.capability)
        assertContentEquals(binding, setup.invocationBindingSha256)
        assertTrue(setup.toString().contains("<redacted>"))
    }

    @Test
    fun `channel setup rejects truncation unsigned limits policy mismatch and timeout expansion`() {
        val payload = AcpProviderBrokerProtocol.channelSetupPayload(capability, policy, binding, 60_000)
        listOf(0, 151, 153).forEach { size ->
            assertFailsWith<AcpProviderProtocolException> { AcpProviderBrokerProtocol.decodeChannelSetupPayload(payload.copyOf(size)) }
        }
        for (offset in 96 until 128 step 4) {
            listOf(0, -1).forEach { value ->
                val mutated = payload.copyOf().also { ByteBuffer.wrap(it).order(ByteOrder.BIG_ENDIAN).putInt(offset, value) }
                assertFailsWith<AcpProviderProtocolException> { AcpProviderBrokerProtocol.decodeChannelSetupPayload(mutated) }
            }
        }
        for (offset in 128 until 152 step 8) {
            listOf(0L, -1L, 1_800_001L).forEach { value ->
                val mutated = payload.copyOf().also { ByteBuffer.wrap(it).order(ByteOrder.BIG_ENDIAN).putLong(offset, value) }
                assertFailsWith<AcpProviderProtocolException> { AcpProviderBrokerProtocol.decodeChannelSetupPayload(mutated) }
            }
        }
        val wrongPolicy = payload.copyOf().also { it[32] = (it[32].toInt() xor 1).toByte() }
        assertFailsWith<AcpProviderProtocolException> { AcpProviderBrokerProtocol.decodeChannelSetupPayload(wrongPolicy, policy) }
        val longerRemaining = payload.copyOf().also { ByteBuffer.wrap(it).order(ByteOrder.BIG_ENDIAN).putLong(128, 120_001) }
        assertFailsWith<AcpProviderProtocolException> { AcpProviderBrokerProtocol.decodeChannelSetupPayload(longerRemaining, policy) }
        assertFailsWith<AcpProviderProtocolException> { AcpProviderBrokerProtocol.channelSetupPayload(capability, policy, binding, 120_001) }
    }

    @Test
    fun `header envelope is closed sanitized status and content type with no trailing fields`() {
        val success = AcpProviderBrokerProtocol.responseHeadersPayload(200, "text/event-stream")
        assertEquals(200, AcpProviderBrokerProtocol.decodeResponseHeadersPayload(success, 256).status)
        assertEquals("text/event-stream", AcpProviderBrokerProtocol.decodeResponseHeadersPayload(success, 256).contentType)
        assertContentEquals(byteArrayOf(1, -111, 0, 0), AcpProviderBrokerProtocol.responseHeadersPayload(401, null))
        listOf(201 to "text/event-stream", 302 to null, 200 to "application/json", 200 to "Text/Event-Stream", 401 to "text/event-stream").forEach {
            assertFailsWith<AcpProviderProtocolException> { AcpProviderBrokerProtocol.responseHeadersPayload(it.first, it.second) }
        }
        assertFailsWith<AcpProviderProtocolException> { AcpProviderBrokerProtocol.decodeResponseHeadersPayload(success + byteArrayOf(0), 256) }
        assertFailsWith<AcpProviderProtocolException> { AcpProviderBrokerProtocol.decodeResponseHeadersPayload(success, success.size - 1) }
    }

    @Test
    fun `terminal codes are exact and unknown payloads are refused`() {
        AcpProviderTerminalKind.entries.forEach { kind ->
            assertEquals(kind, AcpProviderBrokerProtocol.decodeTerminalPayload(AcpProviderBrokerProtocol.terminalPayload(kind)))
        }
        listOf(ByteArray(0), byteArrayOf(0, 0), byteArrayOf(13), byteArrayOf(-1)).forEach { payload ->
            assertFailsWith<AcpProviderProtocolException> { AcpProviderBrokerProtocol.decodeTerminalPayload(payload) }
        }
    }

    @Test
    fun `opening request headers chunks terminal and next monotonic request form one complete exchange`() {
        val order = openedOrder()
        order.accept(AcpProviderFrame(AcpProviderFrameTag.ACP_BYTES, 0, byteArrayOf(1)))
        order.accept(request())
        assertTrue(order.hasActiveRequest())
        order.accept(headers())
        order.accept(chunk(32))
        order.accept(chunk(32))
        order.accept(end(AcpProviderTerminalKind.COMPLETED))
        assertFalse(order.hasActiveRequest())
        order.accept(request(2))
        order.accept(end(AcpProviderTerminalKind.AUTHENTICATION, 2))
        order.finish()
        assertFailsWith<AcpProviderProtocolException> { order.accept(request(3)) }
    }

    @Test
    fun `replayed out of order overlapping and exhausted requests poison the owner`() {
        val operations: List<(AcpProviderFrameOrder) -> Unit> = listOf(
            { it.accept(request(2)) },
            { it.accept(request()); it.accept(request(2)) },
            { it.accept(request()); it.accept(end(AcpProviderTerminalKind.TRANSPORT)); it.accept(request(1)) },
            { it.accept(request()); it.accept(end(AcpProviderTerminalKind.TRANSPORT)); it.accept(request(3)) },
            { it.accept(request()); it.accept(end(AcpProviderTerminalKind.TRANSPORT)); it.accept(request(2));
                it.accept(end(AcpProviderTerminalKind.TRANSPORT, 2)); it.accept(request(3)) },
        )
        operations.forEach { operation ->
            val order = openedOrder()
            assertFailsWith<AcpProviderProtocolException> { operation(order) }
            assertFailsWith<AcpProviderProtocolException> { order.accept(AcpProviderFrame(AcpProviderFrameTag.ACP_BYTES, 0, byteArrayOf(1))) }
        }
    }

    @Test
    fun `response headers chunks terminal and cancellation cannot be reordered or exceed limits`() {
        val operations: List<(AcpProviderFrameOrder) -> Unit> = listOf(
            { it.accept(chunk(1)) },
            { it.accept(end(AcpProviderTerminalKind.COMPLETED)) },
            { it.accept(headers()); it.accept(headers()) },
            { it.accept(headers()); it.accept(chunk(33)) },
            { it.accept(headers()); it.accept(chunk(32)); it.accept(chunk(32)); it.accept(chunk(1)) },
            { it.accept(headers(401)); it.accept(chunk(1)) },
            { it.accept(headers(401)); it.accept(end(AcpProviderTerminalKind.COMPLETED)) },
            { it.accept(headers()); it.accept(end(AcpProviderTerminalKind.COMPLETED)); it.accept(chunk(1)) },
            { it.accept(AcpProviderFrame(AcpProviderFrameTag.PROVIDER_CANCEL, 1, byteArrayOf(1))) },
        )
        operations.forEach { operation ->
            val order = openedOrder().also { it.accept(request()) }
            assertFailsWith<AcpProviderProtocolException> { operation(order) }
        }
    }

    @Test
    fun `response byte budget is cumulative across individually under cap requests`() {
        val order = openedOrder()
        order.accept(request())
        order.accept(headers())
        order.accept(chunk(32))
        order.accept(end(AcpProviderTerminalKind.COMPLETED))
        order.accept(request(2))
        order.accept(headers(sequence = 2))
        order.accept(chunk(16, sequence = 2))
        assertFailsWith<AcpProviderProtocolException> { order.accept(chunk(17, sequence = 2)) }
        assertFailsWith<AcpProviderProtocolException> { order.accept(end(AcpProviderTerminalKind.COMPLETED, 2)) }
    }

    @Test
    fun `cancellation requires a cancellation terminal and unfinished streams are refused`() {
        listOf(AcpProviderTerminalKind.CANCELLED, AcpProviderTerminalKind.REVOKED).forEach { terminal ->
            val order = openedOrder().also { it.accept(request()) }
            order.accept(AcpProviderFrame(AcpProviderFrameTag.PROVIDER_CANCEL, 1, ByteArray(0)))
            order.accept(end(terminal))
            order.finish()
        }
        listOf<(AcpProviderFrameOrder) -> Unit>(
            { it.accept(chunk(1)) },
            { it.accept(headers()) },
            { it.accept(end(AcpProviderTerminalKind.TRANSPORT)) },
            { it.accept(AcpProviderFrame(AcpProviderFrameTag.PROVIDER_CANCEL, 1, ByteArray(0))) },
        ).forEach { operation ->
            val order = openedOrder().also { it.accept(request()); it.accept(AcpProviderFrame(AcpProviderFrameTag.PROVIDER_CANCEL, 1, ByteArray(0))) }
            assertFailsWith<AcpProviderProtocolException> { operation(order) }
        }
        assertFailsWith<AcpProviderProtocolException> { openedOrder().also { it.accept(request()) }.finish() }
        assertFailsWith<AcpProviderProtocolException> { newOrder().finish() }
        assertFailsWith<AcpProviderProtocolException> { newOrder().accept(request()) }
        assertFailsWith<AcpProviderProtocolException> { openedOrder().accept(openFrame()) }
    }

    @Test
    fun `owner rejects different setup policy invocation or capability and a substituted request capability`() {
        for (offset in listOf(0, 32, 64)) {
            val setup = openFrame().payload.also { it[offset] = (it[offset].toInt() xor 1).toByte() }
            val order = newOrder()
            assertFailsWith<AcpProviderProtocolException> { order.accept(AcpProviderFrame(AcpProviderFrameTag.CHANNEL_OPEN, 0, setup)) }
            assertFailsWith<AcpProviderProtocolException> { order.accept(openFrame()) }
        }
        val request = request().payload.also { it[0] = (it[0].toInt() xor 1).toByte() }
        val order = openedOrder()
        assertFailsWith<AcpProviderProtocolException> { order.accept(AcpProviderFrame(AcpProviderFrameTag.PROVIDER_REQUEST, 1, request)) }
        assertFailsWith<AcpProviderProtocolException> { order.accept(this.request()) }
        val bindingInput = binding.copyOf()
        val capabilityInput = capability.copyOf()
        val immutableOwner = AcpProviderFrameOrder(policy, bindingInput, capabilityInput)
        bindingInput.fill(0)
        capabilityInput.fill(0)
        immutableOwner.accept(openFrame())
        immutableOwner.accept(this.request())
    }

    @Test
    fun `zero progress streams fail without spinning and invalid writes emit no partial frame`() {
        val stream = object : InputStream() {
            override fun read(): Int = 0x41
            override fun read(bytes: ByteArray, offset: Int, length: Int): Int = 0
        }
        assertFailsWith<AcpProviderProtocolException> { AcpProviderBrokerProtocol.readFrame(stream, 256, host) }
        val output = ByteArrayOutputStream()
        assertFailsWith<AcpProviderProtocolException> {
            AcpProviderBrokerProtocol.writeFrame(output, AcpProviderFrame(AcpProviderFrameTag.PROVIDER_RESPONSE_END, 1, byteArrayOf(13)), 256, host)
        }
        assertEquals(0, output.size())
    }

    private fun encode(frame: AcpProviderFrame, direction: AcpProviderFrameDirection): ByteArray =
        ByteArrayOutputStream().also { AcpProviderBrokerProtocol.writeFrame(it, frame, 256, direction) }.toByteArray()

    private fun request(sequence: Long = 1): AcpProviderFrame = AcpProviderFrame(AcpProviderFrameTag.PROVIDER_REQUEST,
        sequence, AcpProviderBrokerProtocol.requestPayload(capability, byteArrayOf(1), bounds))
    private fun headers(status: Int = 200, sequence: Long = 1): AcpProviderFrame = AcpProviderFrame(AcpProviderFrameTag.PROVIDER_RESPONSE_HEADERS,
        sequence, AcpProviderBrokerProtocol.responseHeadersPayload(status, if (status == 200) "text/event-stream" else null))
    private fun chunk(size: Int, sequence: Long = 1): AcpProviderFrame = AcpProviderFrame(AcpProviderFrameTag.PROVIDER_RESPONSE_CHUNK, sequence, ByteArray(size))
    private fun end(kind: AcpProviderTerminalKind, sequence: Long = 1): AcpProviderFrame =
        AcpProviderFrame(AcpProviderFrameTag.PROVIDER_RESPONSE_END, sequence, AcpProviderBrokerProtocol.terminalPayload(kind))
    private fun openFrame(): AcpProviderFrame = AcpProviderFrame(AcpProviderFrameTag.CHANNEL_OPEN, 0,
        AcpProviderBrokerProtocol.channelSetupPayload(capability, policy, binding, 60_000))
    private fun newOrder(): AcpProviderFrameOrder = AcpProviderFrameOrder(policy, binding, capability)
    private fun openedOrder(): AcpProviderFrameOrder = newOrder().also { it.accept(openFrame()) }
    private fun header(tag: AcpProviderFrameTag, length: Long): ByteArray = ByteBuffer.allocate(18).order(ByteOrder.BIG_ENDIAN)
        .put(byteArrayOf(0x41, 0x43, 0x50, 0x50, 1, tag.wireCode.toByte()))
        .putLong(if (tag == AcpProviderFrameTag.ACP_BYTES || tag == AcpProviderFrameTag.CHANNEL_OPEN) 0 else 1)
        .putInt(length.toInt()).array()

    private class HeaderOnlyInput(private val header: ByteArray) : InputStream() {
        var consumed = 0
            private set
        override fun read(): Int {
            if (consumed == header.size) throw AssertionError("decoder attempted a payload read")
            return header[consumed++].toInt() and 0xff
        }
        override fun read(bytes: ByteArray, offset: Int, length: Int): Int {
            if (consumed == header.size) throw AssertionError("decoder attempted a payload read")
            val count = minOf(length, header.size - consumed)
            header.copyInto(bytes, offset, consumed, consumed + count)
            consumed += count
            return count
        }
    }
}
