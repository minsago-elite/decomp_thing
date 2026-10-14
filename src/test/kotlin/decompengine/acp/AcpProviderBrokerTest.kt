package decompengine.acp

import decompengine.agent.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.int
import java.net.URI
import java.nio.ByteBuffer
import java.nio.file.Path
import java.time.Duration
import java.util.concurrent.Flow
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.test.*
import org.junit.jupiter.api.Timeout

@Timeout(value = 20, unit = TimeUnit.SECONDS)
class AcpProviderBrokerTest {
    @Test
    fun `duplicate binding revokes idle authority before any further dispatch`() {
        for (identical in listOf(true, false)) {
            val backend = FixtureBackend()
            val broker = open(backend)
            try {
                broker.bindSession("actual-session", "turn-1")
                val cap = capability(broker)
                val originalBinding = bindingHashes(broker)
                val duplicate = runCatching { broker.bindSession(if (identical) "actual-session" else "other-session", "turn-1") }
                val afterDuplicate = broker.snapshot()
                val laterRequest = runCatching { broker.beginRequest(1, cap, body()) }
                assertEquals(0, backend.starts, "duplicate session binding left provider dispatch authority active")
                assertFixedRevoked(duplicate)
                assertIs<AcpProviderBrokerFailure>(laterRequest.exceptionOrNull()).also { assertEquals(AcpProviderTerminalKind.REVOKED, it.kind) }
                assertTrue(afterDuplicate.revoked)
                assertNull(afterDuplicate.admissionDenial, "binding failure must not invent a request sequence")
                assertTrue(afterDuplicate.requests.isEmpty())
                assertEquals(0L, afterDuplicate.wireRequestBytes)
                assertEquals(originalBinding, bindingHashes(broker))
                assertAuthorityRevoked(broker)
                broker.close()
                assertKind(AcpProviderTerminalKind.REVOKED) { broker.beginRequest(1, cap, body()) }
                assertEquals(0, backend.starts)
            } finally { broker.close() }
        }
    }

    @Test
    fun `malformed duplicate identities cannot bypass sticky revocation`() {
        for ((session, turn) in listOf("" to "turn-2", "session-2" to "", "\n" to "turn-2", "s".repeat(257) to "turn-2", "session-2" to "\uD800")) {
            val backend = FixtureBackend()
            val broker = open(backend)
            try {
                broker.bindSession("actual-session", "turn-1")
                val cap = capability(broker)
                val originalBinding = bindingHashes(broker)
                val duplicate = runCatching { broker.bindSession(session, turn) }
                val laterRequest = runCatching { broker.beginRequest(1, cap, body()) }
                assertEquals(0, backend.starts, "malformed duplicate identity left provider dispatch authority active")
                assertFixedRevoked(duplicate)
                assertIs<AcpProviderBrokerFailure>(laterRequest.exceptionOrNull()).also { assertEquals(AcpProviderTerminalKind.REVOKED, it.kind) }
                assertAuthorityRevoked(broker)
                assertEquals(originalBinding, bindingHashes(broker))
                assertTrue(broker.snapshot().requests.isEmpty())
            } finally { broker.close() }
        }
    }

    @Test
    fun `duplicate binding terminates an active or queued streaming exchange once`() {
        for (queued in listOf(false, true)) {
            val backend = FixtureBackend()
            val broker = open(backend)
            try {
                broker.bindSession("actual-session", "turn-1")
                val cap = capability(broker)
                val exchange = broker.beginRequest(1, cap, body())
                val receiver = backend.receiver!!
                if (queued) { backend.headers(); backend.subscribe(); backend.emit(delta("safe candidate!")); assertEquals(1, exchangeQueueSize(exchange)) }
                assertFixedRevoked(runCatching { broker.bindSession("other-session", "other-turn") })
                assertEquals(AcpProviderTerminalKind.REVOKED, exchange.terminal, "duplicate binding must terminate the active exchange")
                assertAuthorityRevoked(broker)
                assertTrue(backend.ownerCancelled)
                assertEquals(queued, backend.subscriptionCancelled)
                assertEquals(0, exchangeQueueSize(exchange))
                val record = broker.snapshot().requests.single()
                assertEquals(AcpProviderTerminalKind.REVOKED, record.terminal)
                assertNull(record.outputTokens)
                assertEquals(0, record.admittedOutputTokens)
                receiver.complete(); receiver.failed(); receiver.timedOut(); exchange.cancel()
                assertEquals(listOf(record), broker.snapshot().requests)
                assertKind(AcpProviderTerminalKind.REVOKED) { exchange.nextChunk() }
                assertKind(AcpProviderTerminalKind.REVOKED) { broker.beginRequest(2, cap, body()) }
                assertEquals(1, backend.starts)
            } finally { broker.close() }
        }
    }

    @Test
    fun `duplicate binding revokes unread EOF completion without losing known usage`() {
        for (consumed in 0..1) {
            val backend = FixtureBackend()
            val broker = open(backend, policy = policy(AcpProviderTransportBounds(maximumChunkBytes = 256, maximumQueuedChunks = 2)))
            try {
                broker.bindSession("actual-session", "turn-1")
                val cap = capability(broker)
                val exchange = broker.beginRequest(1, cap, body())
                val receiver = backend.receiver!!
                backend.headers(); backend.subscribe(); backend.emit(delta("x".repeat(70) + "s")); backend.emit(completed(3)); backend.complete()
                assertEquals(2, exchangeQueueSize(exchange))
                if (consumed == 1) assertEquals(256, exchange.nextChunk()!!.size)
                assertEquals(AcpProviderTerminalKind.COMPLETED, exchange.terminal)
                assertFalse(exchangeRecorded(exchange))
                assertFixedRevoked(runCatching { broker.bindSession("other-session", "other-turn") })
                assertEquals(AcpProviderTerminalKind.REVOKED, exchange.terminal)
                assertAuthorityRevoked(broker)
                val record = broker.snapshot().requests.single()
                assertEquals(AcpProviderTerminalKind.REVOKED, record.terminal)
                assertEquals(3, record.outputTokens)
                assertEquals(3, record.admittedOutputTokens)
                assertEquals(1, record.inputTokens)
                assertEquals(3L, broker.snapshot().outputTokens)
                assertEquals(0, exchangeQueueSize(exchange))
                assertTrue(backend.ownerCancelled && backend.subscriptionCancelled)
                receiver.complete(); receiver.failed(); receiver.timedOut(); exchange.cancel()
                assertEquals(listOf(record), broker.snapshot().requests)
                assertEquals(AcpProviderBrokerCleanup.NOT_ATTEMPTED, broker.snapshot().cleanup)
                assertKind(AcpProviderTerminalKind.REVOKED) { broker.beginRequest(2, cap, body()) }
                backend.clean = false
                assertFailsWith<AcpProviderBrokerCleanupFailure> { broker.close() }
                assertEquals(AcpProviderBrokerCleanup.UNVERIFIED, broker.snapshot().cleanup)
                assertKind(AcpProviderTerminalKind.REVOKED) { broker.beginRequest(2, cap, body()) }
                backend.clean = true; assertFailsWith<AcpProviderBrokerCleanupFailure> { broker.close() }
                assertEquals(AcpProviderBrokerCleanup.UNVERIFIED, broker.snapshot().cleanup)
                assertEquals(listOf(record), broker.snapshot().requests)
                assertKind(AcpProviderTerminalKind.REVOKED) { broker.beginRequest(2, cap, body()) }
                assertEquals(1, backend.starts)
            } finally { backend.clean = true; runCatching { broker.close() } }
        }
    }

    @Test
    fun `duplicate binding preserves recorded completion while revoking only its successor`() {
        for (successor in listOf(false, true)) {
            val backend = FixtureBackend()
            val broker = open(backend)
            try {
                broker.bindSession("actual-session", "turn-1")
                val cap = capability(broker)
                val first = broker.beginRequest(1, cap, body())
                val firstReceiver = backend.receiver!!
                backend.headers(); backend.subscribe(); backend.emit(completed(1)); backend.complete()
                assertNotNull(first.nextChunk())
                val completedRecord = broker.snapshot().requests.single()
                assertEquals(AcpProviderTerminalKind.COMPLETED, completedRecord.terminal)
                val second = if (successor) broker.beginRequest(2, cap, body()).also { backend.headers(); backend.subscribe() } else null
                assertFixedRevoked(runCatching { broker.bindSession("other-session", "other-turn") })
                assertAuthorityRevoked(broker)
                assertEquals(completedRecord, broker.snapshot().requests.first())
                assertNull(first.nextChunk())
                firstReceiver.failed(); firstReceiver.timedOut(); firstReceiver.complete(); first.cancel()
                if (second != null) {
                    assertTrue(backend.ownerCancelled && backend.subscriptionCancelled)
                    assertKind(AcpProviderTerminalKind.REVOKED) { second.nextChunk() }
                    assertEquals(listOf(AcpProviderTerminalKind.COMPLETED, AcpProviderTerminalKind.REVOKED), broker.snapshot().requests.map { it.terminal })
                } else assertEquals(listOf(completedRecord), broker.snapshot().requests)
                broker.close()
                assertEquals(completedRecord, broker.snapshot().requests.first())
                assertKind(AcpProviderTerminalKind.REVOKED) { broker.beginRequest(if (successor) 3 else 2, cap, body()) }
                assertEquals(if (successor) 2 else 1, backend.starts)
            } finally { broker.close() }
        }
    }

    @Test
    fun `malformed initial binding remains unassigned and can be corrected atomically`() {
        for ((session, turn) in listOf("" to "turn-1", "actual-session" to "", "actual-session" to "\uD800")) {
            val backend = FixtureBackend()
            val broker = open(backend)
            try {
                assertFailsWith<IllegalArgumentException> { broker.bindSession(session, turn) }
                assertEquals(null to null, bindingHashes(broker))
                assertFalse(broker.snapshot().revoked)
                broker.bindSession("actual-session", "turn-1")
                val exchange = broker.beginRequest(1, capability(broker), body())
                backend.headers(); backend.subscribe(); backend.emit(completed(1)); backend.complete()
                assertNotNull(exchange.nextChunk()); assertNull(exchange.nextChunk())
                assertEquals(AcpProviderTerminalKind.COMPLETED, broker.snapshot().requests.single().terminal)
                assertEquals(1, backend.starts)
            } finally { broker.close() }
        }
    }

    @Test
    fun `boolean input item is refused before backend dispatch`() {
        assertInputRefused("[false]")
    }

    @Test
    fun `empty object input item is refused before backend dispatch`() {
        assertInputRefused("[{}]")
    }

    @Test
    fun `approved user text input variants preserve values and bounded collections`() {
        val simple = inputMessage("\"fixture\"")
        val native = inputMessage("\"fixture\"", native = true)
        val accepted = listOf(
            "[$simple]", "[$native]", "[$simple,$native]",
            List(16) { simple }.joinToString(",", "[", "]"),
            "[{\"type\":\"message\",\"role\":\"user\",\"content\":" + List(16) { "{\"type\":\"input_text\",\"text\":\"fixture\"}" }.joinToString(",", "[", "]") + "}]",
        )
        accepted.forEach { assertOptionalAccepted("\"input\":$it") }
        for (nativeShape in listOf(false, true)) for (text in listOf(" ", "\n\t\"\\\u0000", "g".repeat(8192), "\uD83D\uDE00".repeat(4096))) {
            assertOptionalAccepted("\"input\":[${inputMessage(requestString(text, 0), nativeShape)}]")
        }
        for (nativeShape in listOf(false, true)) {
            assertOptionalAccepted("\"input\":[${inputMessage("\"\\uD83D\\uDE00\"", nativeShape)}]")
        }
    }

    @Test
    fun `unsupported input items roles keys and content shapes are refused before dispatch`() {
        val invalid = mutableListOf("null", "false", "0", "\"fixture\"", "{}", "[]", "[null]", "[0]", "[\"fixture\"]", "[[]]")
        for (message in listOf(
            "{\"role\":\"user\"}", "{\"content\":\"fixture\"}", "{\"role\":\"user\",\"content\":\"fixture\",\"extra\":true}",
            "{\"role\":\"user\",\"content\":[]}", "{\"type\":\"message\",\"role\":\"user\",\"content\":\"fixture\"}",
            "{\"type\":\"message\",\"role\":\"user\"}", "{\"type\":\"message\",\"content\":[]}",
            "{\"type\":\"message\",\"role\":\"user\",\"content\":[],\"status\":\"completed\"}",
            "{\"type\":\"function_call\",\"call_id\":\"fixture\",\"name\":\"fixture\",\"arguments\":\"{}\"}",
            "{\"type\":\"function_call_output\",\"call_id\":\"fixture\",\"output\":\"fixture\"}",
        )) invalid += "[$message]"
        for (nativeShape in listOf(false, true)) {
            for (role in listOf("null", "false", "0", "[]", "{}", "\"assistant\"", "\"system\"", "\"developer\"", "\"tool\"", "\" user\"")) {
                invalid += "[" + inputMessage("\"fixture\"", nativeShape).replace("\"role\":\"user\"", "\"role\":$role") + "]"
            }
            for (content in listOf("null", "false", "0", "{}", "[]")) {
                invalid += if (nativeShape) "[{\"type\":\"message\",\"role\":\"user\",\"content\":$content}]"
                    else "[{\"role\":\"user\",\"content\":$content}]"
            }
        }
        for (type in listOf("null", "false", "0", "[]", "{}", "\"function_call\"", "\"message \"")) {
            invalid += "[" + inputMessage("\"fixture\"", true).replace("\"type\":\"message\"", "\"type\":$type") + "]"
        }
        for (part in listOf("null", "false", "0", "\"fixture\"", "[]", "{}", "{\"type\":\"input_text\"}", "{\"text\":\"fixture\"}", "{\"type\":\"input_text\",\"text\":\"fixture\",\"extra\":true}")) {
            invalid += "[{\"type\":\"message\",\"role\":\"user\",\"content\":[$part]}]"
        }
        for (type in listOf("null", "false", "0", "[]", "{}", "\"output_text\"", "\"input_image\"", "\"input_audio\"")) {
            invalid += "[" + inputMessage("\"fixture\"", true).replace("\"type\":\"input_text\"", "\"type\":$type") + "]"
        }
        for (text in listOf("null", "false", "0", "[]", "{}")) invalid += "[${inputMessage(text, true)}]"
        invalid.forEach { assertInputRefused(it) }
        assertInputRefused("[${inputMessage("\"fixture\"")},false]")
    }

    @Test
    fun `input counts empty text and malformed Unicode refuse before dispatch`() {
        assertInputRefused(List(17) { inputMessage("\"fixture\"") }.joinToString(",", "[", "]"))
        assertInputRefused("[{\"type\":\"message\",\"role\":\"user\",\"content\":" + List(17) { "{\"type\":\"input_text\",\"text\":\"fixture\"}" }.joinToString(",", "[", "]") + "}]")
        for (nativeShape in listOf(false, true)) {
            assertInputRefused("[${inputMessage("\"\"", nativeShape)}]")
            for (escaped in listOf("\\uD800", "\\uDC00", "\\uD800A", "A\\uDC00", "\\uDC00\\uD800", "\\uD800\\uD800", "\\uD83D\\uDE00\\uD800")) {
                val input = "[${inputMessage("\"$escaped\"", nativeShape)}]"
                assertTrue(rawInputRequest(input).decodeToString().contains(escaped), "ASCII JSON escapes must reach the broker unchanged")
                assertInputRefused(input)
            }
            assertInputRefused("[${inputMessage(requestString("g".repeat(8192), 0), nativeShape)}]", AcpProviderTerminalKind.RESOURCE_EXHAUSTED,
                policy(AcpProviderTransportBounds(maximumRequestBytes = 8192)))
        }
    }

    @Test
    fun `input admission retains global parser and exact transformed byte limits`() {
        assertInputRefused("[{\"role\":\"user\",\"content\":\"fixture\",\"content\":\"duplicate\"}]", AcpProviderTerminalKind.MALFORMED_REQUEST)
        assertInputRefused("[{\"role\":\"user\",\"\\u0072ole\":\"user\",\"content\":\"fixture\"}]", AcpProviderTerminalKind.MALFORMED_REQUEST)
        assertInputRefused("[".repeat(65) + "false" + "]".repeat(65), AcpProviderTerminalKind.MALFORMED_REQUEST)
        assertInputRefused(List(100_001) { "false" }.joinToString(",", "[", "]"), AcpProviderTerminalKind.MALFORMED_REQUEST)
        val utf8Fixture = rawInputRequest("[${inputMessage("\"marker\"")}]")
        val marker = utf8Fixture.decodeToString().indexOf("marker")
        assertInputRequestRefused(utf8Fixture.copyOfRange(0, marker) + byteArrayOf(0xc3.toByte()) + utf8Fixture.copyOfRange(marker + 6, utf8Fixture.size), AcpProviderTerminalKind.MALFORMED_REQUEST, policy())
        for (nativeShape in listOf(false, true)) {
            val request = rawInputRequest("[${inputMessage("\"byte fixture\"", nativeShape)}]")
            val wire = kotlinx.serialization.json.JsonObject(Json.parseToJsonElement(request.decodeToString()).jsonObject +
                ("max_output_tokens" to kotlinx.serialization.json.JsonPrimitive(32))).toString().toByteArray()
            for (limit in listOf(wire.size, wire.size - 1, request.size - 1)) {
                val backend = FixtureBackend()
                val broker = open(backend, policy = policy(AcpProviderTransportBounds(maximumRequestBytes = limit)), outputTokens = 32)
                try {
                    broker.bindSession("actual-session", "turn-1")
                    if (limit == wire.size) {
                        val exchange = broker.beginRequest(1, capability(broker), request)
                        assertContentEquals(wire, backend.lastRequest!!.body)
                        backend.headers(); backend.subscribe(); backend.emit(completed(1)); backend.complete()
                        assertNotNull(exchange.nextChunk()); assertNull(exchange.nextChunk())
                        assertEquals(1, backend.starts)
                    } else {
                        assertKind(AcpProviderTerminalKind.RESOURCE_EXHAUSTED) { broker.beginRequest(1, capability(broker), request) }
                        assertEquals(0, backend.starts)
                        assertNull(backend.lastRequest)
                    }
                } finally { broker.close() }
            }
        }
    }

    @Test
    fun `decoded capability in native text input refuses before dispatch`() {
        for (case in 0..2) for (escape in 0..2) {
            val backend = FixtureBackend()
            val broker = open(backend)
            try {
                broker.bindSession("actual-session", "turn-1")
                val cap = capability(broker)
                val secret = cap.joinToString("") { "%02x".format(it) }
                val spelling = when (case) {
                    1 -> secret.uppercase()
                    2 -> secret.mapIndexed { index, character -> if (index % 2 == 0) character.uppercaseChar() else character }.joinToString("")
                    else -> secret
                }
                val request = rawInputRequest("[${inputMessage(requestString(spelling, escape), true)}]")
                val failure = assertFailsWith<AcpProviderBrokerFailure> { broker.beginRequest(1, cap, request) }
                assertEquals(AcpProviderTerminalKind.SECRET_EXPOSURE, failure.kind)
                assertNull(failure.cause)
                assertFalse(failure.toString().contains(secret, ignoreCase = true))
                assertEquals(0, backend.starts)
                assertNull(backend.lastRequest)
                assertTrue(broker.snapshot().requests.isEmpty())
                assertEquals(0L, broker.snapshot().wireRequestBytes)
                assertEquals(0L, broker.snapshot().outputTokens)
            } finally { broker.close() }
        }
    }

    @Test
    fun `quoted parallel tool call flag is refused before backend dispatch`() {
        assertOptionalRefused("\"parallel_tool_calls\":\"false\"")
    }

    @Test
    fun `supported optional scalar and text shapes preserve admitted wire values`() {
        val accepted = listOf(
            "\"instructions\":\"\"", "\"instructions\":" + requestString("i".repeat(4096), 0),
            "\"prompt_cache_key\":\"\"", "\"prompt_cache_key\":" + requestString("c".repeat(128), 0),
            "\"safety_identifier\":\"\"", "\"safety_identifier\":" + requestString("s".repeat(128), 0),
            "\"parallel_tool_calls\":false", "\"parallel_tool_calls\":true", "\"truncation\":\"disabled\"",
            "\"include\":[]", "\"include\":[\"reasoning.encrypted_content\"]", "\"metadata\":{}",
            "\"service_tier\":\"auto\"", "\"text\":{}", "\"text\":{\"verbosity\":\"medium\"}",
            "\"text\":{\"format\":{\"type\":\"text\"}}", "\"text\":{\"verbosity\":\"medium\",\"format\":{\"type\":\"text\"}}",
            "\"tools\":[]", "\"tool_choice\":\"auto\"", "\"tool_choice\":\"none\"",
            "\"metadata\":{" + (0 until 16).joinToString(",") { "\"key$it\":\"value\"" } + "}",
            "\"metadata\":{" + requestString("k".repeat(64), 0) + ":" + requestString("v".repeat(512), 0) + "}",
        )
        accepted.forEach(::assertOptionalAccepted)
        for (summary in listOf("auto", "concise", "detailed")) {
            assertOptionalAccepted("\"reasoning\":{\"effort\":\"low\",\"summary\":\"$summary\"}")
        }
        assertOptionalAccepted(""""instructions":"fixture instructions","prompt_cache_key":"cache","safety_identifier":"safety","parallel_tool_calls":false,"truncation":"disabled","include":["reasoning.encrypted_content"],"metadata":{"fixture":"safe"},"service_tier":"auto","text":{"verbosity":"medium","format":{"type":"text"}},"tools":[${functionTool()}],"tool_choice":{"type":"function","name":"fixture"}""")
    }

    @Test
    fun `optional field type confusion and unsupported modes are refused before dispatch`() {
        val invalid = mutableListOf<String>()
        for (field in listOf("instructions", "prompt_cache_key", "safety_identifier", "service_tier", "truncation")) {
            for (value in listOf("null", "false", "0", "[]", "{}")) invalid += "\"$field\":$value"
        }
        for (value in listOf("null", "\"false\"", "0", "[]", "{}")) invalid += "\"parallel_tool_calls\":$value"
        for (value in listOf("null", "\"reasoning.encrypted_content\"", "{}", "false", "[null]", "[1]", "[{}]", "[\"unknown\"]", "[\"reasoning.encrypted_content\",\"reasoning.encrypted_content\"]")) invalid += "\"include\":$value"
        for (value in listOf("null", "[]", "\"text\"", "false", "{\"verbosity\":null}", "{\"verbosity\":1}", "{\"verbosity\":\"high\"}", "{\"format\":null}", "{\"format\":\"text\"}", "{\"format\":{\"type\":1}}", "{\"format\":{\"type\":\"json_object\"}}", "{\"format\":{\"type\":\"text\",\"extra\":true}}", "{\"unknown\":false}")) invalid += "\"text\":$value"
        for (value in listOf("null", "[]", "true", "\"low\"", "{\"effort\":\"low\",\"summary\":null}", "{\"effort\":\"low\",\"summary\":false}", "{\"effort\":\"low\",\"summary\":\"unknown\"}", "{\"effort\":\"low\",\"unknown\":true}")) invalid += "\"reasoning\":$value"
        invalid += listOf("\"truncation\":\"auto\"", "\"service_tier\":\"priority\"", "\"unknown\":true")
        invalid.forEach(::assertOptionalRefused)
    }

    @Test
    fun `optional string and metadata bounds are enforced before dispatch`() {
        listOf(
            "\"instructions\":" + requestString("i".repeat(4097), 0),
            "\"prompt_cache_key\":" + requestString("c".repeat(129), 0),
            "\"safety_identifier\":" + requestString("s".repeat(129), 0),
            "\"metadata\":null", "\"metadata\":[]", "\"metadata\":false", "\"metadata\":\"value\"",
            "\"metadata\":{\"\":\"value\"}", "\"metadata\":{\"key\":null}", "\"metadata\":{\"key\":false}",
            "\"metadata\":{\"key\":0}", "\"metadata\":{\"key\":[]}", "\"metadata\":{\"key\":{}}",
            "\"metadata\":{" + requestString("k".repeat(65), 0) + ":\"value\"}",
            "\"metadata\":{\"key\":" + requestString("v".repeat(513), 0) + "}",
            "\"metadata\":{" + (0 until 17).joinToString(",") { "\"key$it\":\"value\"" } + "}",
        ).forEach(::assertOptionalRefused)
    }

    @Test
    fun `closed function tools and choices preserve bounded primitive schemas`() {
        val property = """{"type":"string","description":"fixture","enum":["one","two"]}"""
        val properties = """{"text":$property,"number":{"type":"number"},"integer":{"type":"integer"},"flag":{"type":"boolean"}}"""
        val schema = parameterSchema(properties, "[\"text\",\"number\",\"integer\",\"flag\"]")
        for (strict in listOf("", ",\"strict\":false", ",\"strict\":true")) {
            val tool = functionTool(schema = schema, suffix = strict + ",\"description\":" + requestString("d".repeat(1024), 0))
            for (choice in listOf("\"auto\"", "\"none\"", "\"required\"", "{\"type\":\"function\",\"name\":\"fixture\"}")) {
                assertOptionalAccepted("\"tools\":[$tool],\"tool_choice\":$choice")
            }
        }
        assertOptionalAccepted("\"tools\":[${functionTool()}]")
        assertOptionalAccepted("\"tools\":[${functionTool(schema = parameterSchema(properties))}]")
        assertOptionalAccepted("\"tools\":[" + (0 until 16).joinToString(",") { functionTool(name = "tool_$it") } + "]")
        assertOptionalAccepted("\"tools\":[${functionTool(name = "n".repeat(64))}]")
        val boundedProperties = "{" + (0 until 32).joinToString(",") { "\"p$it\":{\"type\":\"boolean\"}" } + "}"
        assertOptionalAccepted("\"tools\":[${functionTool(schema = parameterSchema(boundedProperties))}]")
        val enum = (0 until 16).joinToString(",", "[", "]") { requestString("e".repeat(126) + "%02d".format(it), 0) }
        val boundedProperty = "{" + requestString("p".repeat(64), 0) + ":{\"type\":\"string\",\"description\":" + requestString("d".repeat(1024), 0) + ",\"enum\":$enum}}"
        assertOptionalAccepted("\"tools\":[${functionTool(schema = parameterSchema(boundedProperty))}]")
    }

    @Test
    fun `unsupported function tool and choice shapes are refused before dispatch`() {
        val invalid = mutableListOf("\"tools\":null", "\"tools\":{}", "\"tools\":false", "\"tools\":\"function\"", "\"tools\":[null]", "\"tools\":[false]", "\"tools\":[[]]", "\"tools\":[{}]", "\"tools\":[{\"type\":\"function\"}]")
        for (tool in listOf(
            functionTool().replace("\"function\"", "\"custom\""), functionTool().replace("\"function\"", "null"),
            functionTool(name = ""), functionTool(name = "invalid name"), functionTool(name = "n".repeat(65)),
            functionTool().replace("\"fixture\"", "0"), functionTool().replace("\"fixture\"", "null"),
            functionTool(suffix = ",\"strict\":\"false\""), functionTool(suffix = ",\"strict\":null"),
            functionTool(suffix = ",\"description\":null"), functionTool(suffix = ",\"description\":[]"),
            functionTool(suffix = ",\"description\":" + requestString("d".repeat(1025), 0)),
            functionTool(suffix = ",\"defer_loading\":false"), functionTool(suffix = ",\"unknown\":true"),
        )) invalid += "\"tools\":[$tool]"
        for (key in listOf("type", "name", "parameters")) {
            val tool = kotlinx.serialization.json.JsonObject(Json.parseToJsonElement(functionTool()).jsonObject - key)
            invalid += "\"tools\":[$tool]"
        }
        for (key in listOf("type", "properties", "required", "additionalProperties")) {
            val schema = kotlinx.serialization.json.JsonObject(Json.parseToJsonElement(parameterSchema()).jsonObject - key)
            invalid += "\"tools\":[${functionTool(schema = schema.toString())}]"
        }
        for (schema in listOf(
            "null", "[]", "{}", "\"schema\"", parameterSchema().dropLast(1) + ",\"\$ref\":\"fixture\"}",
            parameterSchema().replace("\"object\"", "[\"object\"]"), parameterSchema().replace("\"object\"", "\"array\""),
            parameterSchema().replace("false", "true"), parameterSchema().replace("false", "\"false\""),
            parameterSchema(properties = "[]"), parameterSchema(required = "null"), parameterSchema(required = "{}"),
            parameterSchema(required = "[null]"), parameterSchema(required = "[\"missing\"]"),
            parameterSchema("{\"p\":{\"type\":\"string\"}}", "[\"p\",\"p\"]"),
            parameterSchema("{" + (0 until 33).joinToString(",") { "\"p$it\":{\"type\":\"boolean\"}" } + "}"),
            parameterSchema("{" + requestString("p".repeat(65), 0) + ":{\"type\":\"string\"}}"),
            parameterSchema("{\"bad name\":{\"type\":\"string\"}}"),
        )) invalid += "\"tools\":[${functionTool(schema = schema)}]"
        for (property in listOf(
            "null", "[]", "\"string\"", "{}", "{\"type\":null}", "{\"type\":[\"string\"]}",
            "{\"type\":\"object\"}", "{\"type\":\"array\"}", "{\"type\":\"string\",\"unknown\":false}",
            "{\"type\":\"string\",\"description\":null}", "{\"type\":\"string\",\"description\":" + requestString("d".repeat(1025), 0) + "}",
            "{\"type\":\"string\",\"enum\":null}", "{\"type\":\"string\",\"enum\":{}}", "{\"type\":\"string\",\"enum\":[]}",
            "{\"type\":\"string\",\"enum\":[null]}", "{\"type\":\"string\",\"enum\":[0]}", "{\"type\":\"string\",\"enum\":[\"same\",\"same\"]}",
            "{\"type\":\"number\",\"enum\":[\"one\"]}", "{\"type\":\"string\",\"enum\":[" + requestString("e".repeat(129), 0) + "]}",
            "{\"type\":\"string\",\"enum\":[" + (0 until 17).joinToString(",") { "\"e$it\"" } + "]}",
        )) invalid += "\"tools\":[${functionTool(schema = parameterSchema("{\"p\":$property}"))}]"
        invalid += "\"tools\":[${functionTool(schema = parameterSchema("{\"p\":{\"type\":\"string\"}}"), suffix = ",\"strict\":true")}]"
        invalid += "\"tools\":[${functionTool()},${functionTool()}]"
        invalid += "\"tools\":[" + (0 until 17).joinToString(",") { functionTool(name = "tool_$it") } + "]"
        for (choice in listOf("null", "false", "0", "[]", "\"unsupported\"", "\"required\"", "{}", "{\"type\":\"function\",\"name\":\"fixture\"}")) invalid += "\"tool_choice\":$choice"
        for (choice in listOf("{\"type\":\"function\"}", "{\"type\":\"function\",\"name\":null}", "{\"type\":\"function\",\"name\":\"other\"}", "{\"type\":\"custom\",\"name\":\"fixture\"}", "{\"type\":\"function\",\"name\":\"fixture\",\"extra\":true}")) invalid += "\"tools\":[${functionTool()}],\"tool_choice\":$choice"
        invalid.forEach(::assertOptionalRefused)
    }

    @Test
    fun `optional request documents retain strict duplicate depth token and byte admission`() {
        val base = body().decodeToString().dropLast(1)
        val malformed = listOf(
            "$base,\"parallel_tool_calls\":true,\"parallel_tool_calls\":false}",
            "$base,\"metadata\":" + "[".repeat(65) + "0" + "]".repeat(65) + "}",
            "$base,\"metadata\":[" + List(100_001) { "0" }.joinToString(",") + "]}",
            "$base,\"metadata\":{\"number\":" + "1".repeat(129) + "}}",
        )
        for (request in malformed) {
            val backend = FixtureBackend()
            val broker = open(backend)
            try {
                broker.bindSession("actual-session", "turn-1")
                assertKind(AcpProviderTerminalKind.MALFORMED_REQUEST) { broker.beginRequest(1, capability(broker), request.toByteArray()) }
                assertEquals(0, backend.starts)
                assertNull(backend.lastRequest)
                assertTrue(broker.snapshot().requests.isEmpty())
            } finally { broker.close() }
        }
        val request = optionalRequest("\"instructions\":\"byte bound fixture\"")
        val wire = kotlinx.serialization.json.JsonObject(Json.parseToJsonElement(request.decodeToString()).jsonObject +
            ("max_output_tokens" to kotlinx.serialization.json.JsonPrimitive(32))).toString().toByteArray()
        for (byteLimit in listOf(wire.size, request.size - 1)) {
            val backend = FixtureBackend()
            val broker = open(backend, policy = policy(AcpProviderTransportBounds(maximumRequestBytes = byteLimit)), outputTokens = 32)
            try {
                broker.bindSession("actual-session", "turn-1")
                if (byteLimit == wire.size) {
                    val exchange = broker.beginRequest(1, capability(broker), request)
                    assertContentEquals(wire, backend.lastRequest!!.body)
                    backend.headers(); backend.subscribe(); backend.emit(completed(1)); backend.complete()
                    assertNotNull(exchange.nextChunk()); assertNull(exchange.nextChunk())
                    assertEquals(1, backend.starts)
                } else {
                    assertKind(AcpProviderTerminalKind.RESOURCE_EXHAUSTED) { broker.beginRequest(1, capability(broker), request) }
                    assertEquals(0, backend.starts)
                    assertNull(backend.lastRequest)
                }
            } finally { broker.close() }
        }
    }

    @Test
    fun `invocation capability in decoded request names and values is refused before dispatch`() {
        for (location in 0..3) for (case in 0..2) for (escapeMode in 0..2) {
            val backend = FixtureBackend()
            val broker = open(backend)
            try {
                broker.bindSession("actual-session", "turn-1")
                val cap = capability(broker)
                val secret = cap.joinToString("") { "%02x".format(it) }
                val value = when (case) {
                    1 -> secret.uppercase()
                    2 -> secret.mapIndexed { index, character -> if (index % 2 == 0) character.uppercaseChar() else character }.joinToString("")
                    else -> secret
                }
                val encoded = requestString(value, escapeMode)
                val base = body().decodeToString()
                val request = when (location) {
                    0 -> base.replace("\"synthetic fixture\"", encoded)
                    1 -> base.dropLast(1) + ",\"instructions\":$encoded}"
                    2 -> base.dropLast(1) + ",\"metadata\":{\"safe\":[{\"nested\":$encoded}]}}"
                    else -> base.dropLast(1) + ",\"metadata\":{$encoded:\"safe\"}}"
                }
                val failure = assertFailsWith<AcpProviderBrokerFailure> { broker.beginRequest(1, cap, request.toByteArray()) }
                assertEquals(AcpProviderTerminalKind.SECRET_EXPOSURE, failure.kind)
                assertNull(failure.cause)
                assertFalse(failure.toString().contains(secret, ignoreCase = true))
                assertFalse(failure.toString().contains(encoded))
                assertEquals(0, backend.starts)
                assertNull(backend.lastRequest)
                val evidence = broker.snapshot()
                assertTrue(evidence.revoked)
                assertEquals(AcpProviderTerminalKind.SECRET_EXPOSURE, evidence.admissionDenial!!.terminal)
                assertTrue(evidence.requests.isEmpty())
                assertEquals(0L, evidence.wireRequestBytes)
                assertEquals(0L, evidence.outputTokens)
            } finally { broker.close() }
        }
    }

    @Test
    fun `safe capability prefixes and near matches remain admissible without disclosure`() {
        for (nearMatch in listOf(false, true)) for (escaped in listOf(false, true)) {
            val backend = FixtureBackend()
            val broker = open(backend)
            try {
                broker.bindSession("actual-session", "turn-1")
                val cap = capability(broker)
                val secret = cap.joinToString("") { "%02x".format(it) }
                val safe = if (nearMatch) secret.dropLast(1) + if (secret.last() == '0') '1' else '0'
                    else secret.take(63) + "!"
                val request = body().decodeToString().dropLast(1) + ",\"instructions\":" + requestString(safe, if (escaped) 1 else 0) + "}"
                val exchange = broker.beginRequest(1, cap, request.toByteArray())
                assertEquals(1, backend.starts)
                backend.headers(); backend.subscribe(); backend.emit(completed(1)); backend.complete()
                assertNotNull(exchange.nextChunk()); assertNull(exchange.nextChunk())
                assertEquals(AcpProviderTerminalKind.COMPLETED, broker.snapshot().requests.single().terminal)
            } finally { broker.close() }
        }
    }

    @Test
    fun `reported output exceeding a smaller declared request bound is refused before completion`() {
        val backend = FixtureBackend()
        val broker = open(backend, outputTokens = 8)
        try {
            broker.bindSession("actual-session", "turn-1")
            val request = body().decodeToString().dropLast(1) + ",\"max_output_tokens\":2}"
            val exchange = broker.beginRequest(1, capability(broker), request.toByteArray())
            assertEquals(2, Json.parseToJsonElement(backend.lastRequest!!.body.decodeToString()).jsonObject.getValue("max_output_tokens").jsonPrimitive.int)
            backend.headers(); backend.subscribe(); backend.emit(completed(3)); backend.complete()
            assertKind(AcpProviderTerminalKind.RESOURCE_EXHAUSTED) { exchange.nextChunk() }
            assertTrue(backend.cancelled)
            assertEquals(1, backend.starts)
            val evidence = broker.snapshot()
            assertTrue(evidence.revoked)
            assertEquals(0L, evidence.outputTokens)
            assertEquals(0, evidence.requests.single().admittedOutputTokens)
            assertEquals(AcpProviderTerminalKind.RESOURCE_EXHAUSTED, evidence.requests.single().terminal)
        } finally { broker.close() }
    }

    @Test
    fun `exact declared output bound and default cumulative remainder retain their limits`() {
        for (firstUsage in 0..2) {
        val backend = FixtureBackend()
        val broker = open(backend, outputTokens = 6)
        try {
            broker.bindSession("actual-session", "turn-1")
            val cap = capability(broker)
            val request = body().decodeToString().dropLast(1) + ",\"max_output_tokens\":2}"
            val first = broker.beginRequest(1, cap, request.toByteArray())
            backend.headers(); backend.subscribe(); backend.emit(completed(firstUsage)); backend.complete()
            assertNotNull(first.nextChunk()); assertNull(first.nextChunk())
            val second = broker.beginRequest(2, cap, body())
            val remaining = 6 - firstUsage
            assertEquals(remaining, Json.parseToJsonElement(backend.lastRequest!!.body.decodeToString()).jsonObject.getValue("max_output_tokens").jsonPrimitive.int)
            backend.headers(); backend.subscribe(); backend.emit(completed(remaining)); backend.complete()
            assertNotNull(second.nextChunk()); assertNull(second.nextChunk())
            assertEquals(6L, broker.snapshot().outputTokens)
            assertEquals(listOf(firstUsage, remaining), broker.snapshot().requests.map { it.admittedOutputTokens })
            assertKind(AcpProviderTerminalKind.RESOURCE_EXHAUSTED) { broker.beginRequest(3, cap, body()) }
            assertEquals(2, backend.starts)
        } finally { broker.close() }
        }
    }

    @Test
    fun `invalid declared request output limits are refused before backend dispatch`() {
        for (limit in listOf("0", "-1", "9", "\"2\"", "2.5", "true", "null", "[]")) {
            val backend = FixtureBackend()
            val broker = open(backend, outputTokens = 8)
            try {
                broker.bindSession("actual-session", "turn-1")
                val request = body().decodeToString().dropLast(1) + ",\"max_output_tokens\":$limit}"
                assertKind(AcpProviderTerminalKind.UNSUPPORTED_OPERATION) { broker.beginRequest(1, capability(broker), request.toByteArray()) }
                assertEquals(0, backend.starts)
                assertNull(backend.lastRequest)
                assertTrue(broker.snapshot().requests.isEmpty())
            } finally { broker.close() }
        }
    }

    @Test
    fun `throwing cancellation callback revokes a stalled exchange without consumer progress`() {
        val failCallback = AtomicBoolean(false)
        val backend = FixtureBackend()
        val broker = open(backend, cancellation = AgentCancellation {
            if (failCallback.get()) throw IllegalStateException(TEST_TOKEN)
            false
        })
        try {
            broker.bindSession("actual-session", "turn-1")
            val exchange = broker.beginRequest(1, capability(broker), body())
            backend.headers(); backend.subscribe()
            failCallback.set(true)
            await { broker.snapshot().revoked }
            assertTrue(backend.cancelled)
            val failure = assertFailsWith<AcpProviderBrokerFailure> { exchange.nextChunk() }
            assertEquals(AcpProviderTerminalKind.TRANSPORT, failure.kind)
            assertNull(failure.cause)
            assertFalse(failure.toString().contains(TEST_TOKEN))
            assertEquals(AcpProviderTerminalKind.TRANSPORT, broker.snapshot().requests.single().terminal)
            assertEquals(1, backend.starts)
        } finally { broker.close() }
    }

    @Test
    fun `quoted output token limit is refused before backend dispatch`() {
        val backend = FixtureBackend()
        val broker = open(backend)
        try {
            broker.bindSession("actual-session", "turn-1")
            val cap = capability(broker)
            val malformed = body().decodeToString().dropLast(1) + ",\"max_output_tokens\":\"5\"}"
            assertKind(AcpProviderTerminalKind.UNSUPPORTED_OPERATION) { broker.beginRequest(1, cap, malformed.toByteArray()) }
            assertEquals(0, backend.starts)
            assertTrue(broker.snapshot().requests.isEmpty())
            assertEquals(AcpProviderTerminalKind.UNSUPPORTED_OPERATION, broker.snapshot().admissionDenial!!.terminal)
        } finally { broker.close() }
    }

    @Test
    fun `interrupted backend cleanup preserves cancellation and unverified cleanup`() {
        val backend = FixtureBackend(interruptCleanup = true)
        val broker = open(backend)
        try {
            assertFalse(Thread.currentThread().isInterrupted)
            assertFailsWith<AcpProviderBrokerCleanupFailure> { broker.close() }
            assertTrue(Thread.currentThread().isInterrupted)
            assertEquals(AcpProviderBrokerCleanup.UNVERIFIED, broker.snapshot().cleanup)
            assertTrue(broker.snapshot().revoked)
        } finally {
            Thread.interrupted()
            backend.interruptCleanup = false
            assertFailsWith<AcpProviderBrokerCleanupFailure> { broker.close() }
        }
    }

    @Test
    fun `interrupted lifecycle cleanup preserves cancellation and unverified cleanup`() {
        val broker = open(FixtureBackend())
        val started = CountDownLatch(1)
        val release = CountDownLatch(1)
        // Keep the real owner alive through shutdownNow so awaitTermination, rather than only
        // backend cleanup, must observe the caller's interrupt. No production injection seam.
        val lifecycle = AcpProviderBroker::class.java.getDeclaredField("lifecycle").let {
            it.isAccessible = true
            it.get(broker) as ScheduledThreadPoolExecutor
        }
        lifecycle.execute {
            started.countDown()
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
            while (release.count > 0 && System.nanoTime() < deadline) {
                try { release.await(10, TimeUnit.MILLISECONDS) } catch (_: InterruptedException) { }
            }
        }
        try {
            assertTrue(started.await(1, TimeUnit.SECONDS))
            Thread.currentThread().interrupt()
            assertFailsWith<AcpProviderBrokerCleanupFailure> { broker.close() }
            assertTrue(Thread.currentThread().isInterrupted)
            assertEquals(AcpProviderBrokerCleanup.UNVERIFIED, broker.snapshot().cleanup)
        } finally {
            Thread.interrupted()
            release.countDown()
            assertFailsWith<AcpProviderBrokerCleanupFailure> { broker.close() }
        }
    }

    @Test
    fun `exactly exhausted input token budget refuses the next request before dispatch`() {
        val backend = FixtureBackend()
        val broker = open(backend, inputTokens = 1)
        try {
            broker.bindSession("actual-session", "turn-1")
            val cap = capability(broker)
            val first = broker.beginRequest(1, cap, body())
            backend.headers(); backend.subscribe(); backend.emit(completed(1)); backend.complete()
            assertNotNull(first.nextChunk()); assertNull(first.nextChunk())
            assertEquals(1, broker.snapshot().requests.single().inputTokens)
            assertKind(AcpProviderTerminalKind.RESOURCE_EXHAUSTED) { broker.beginRequest(2, cap, body()) }
            assertEquals(1, backend.starts)
            assertEquals(AcpProviderTerminalKind.RESOURCE_EXHAUSTED, broker.snapshot().admissionDenial!!.terminal)
            assertEquals(AcpProviderTerminalKind.COMPLETED, broker.snapshot().requests.single().terminal)
        } finally { broker.close() }
    }

    @Test
    fun `completed final chunk freezes evidence before a later cancellation close or callback`() {
        for (scenario in 0..3) {
            val backend = FixtureBackend()
            val cancelled = AgentCancellationSource()
            val broker = open(backend, cancellation = cancelled.cancellation)
            try {
                broker.bindSession("actual-session", "turn-1")
                val exchange = broker.beginRequest(1, capability(broker), body())
                backend.headers(); backend.subscribe(); backend.emit(completed(1)); backend.complete()
                assertNotNull(exchange.nextChunk())
                assertEquals(AcpProviderTerminalKind.COMPLETED, broker.snapshot().requests.single().terminal)
                when (scenario) {
                    0 -> { cancelled.cancel(); await { broker.snapshot().revoked } }
                    1 -> broker.close()
                    2 -> exchange.cancel()
                    else -> backend.receiver!!.failed()
                }
                assertNull(exchange.nextChunk())
                assertEquals(AcpProviderTerminalKind.COMPLETED, broker.snapshot().requests.single().terminal)
                assertEquals(1, broker.snapshot().requests.size)
            } finally { broker.close() }
        }
    }

    @Test
    fun `validated completion with undelivered chunks remains cancellable`() {
        val backend = FixtureBackend()
        val broker = open(backend)
        try {
            broker.bindSession("actual-session", "turn-1")
            val exchange = broker.beginRequest(1, capability(broker), body())
            backend.headers(); backend.subscribe(); backend.emit(completed(1)); backend.complete()
            exchange.cancel()
            assertKind(AcpProviderTerminalKind.CANCELLED) { exchange.nextChunk() }
            assertEquals(AcpProviderTerminalKind.CANCELLED, broker.snapshot().requests.single().terminal)
        } finally { broker.close() }
    }

    @Test
    fun `idle monitor expires completed exchanges with all chunks unread`() {
        assertCompletedQueueIdleExpiry(consumedChunks = 0)
    }

    @Test
    fun `idle monitor expires completed exchanges with one final chunk unread`() {
        assertCompletedQueueIdleExpiry(consumedChunks = 1)
    }

    @Test
    fun `idle monitoring cannot rewrite fully delivered completion or revoke its successor`() {
        val backend = FixtureBackend()
        val monitor = LifecycleObservation()
        val bounds = AcpProviderTransportBounds()
        val broker = open(backend, policy = policy(bounds), cancellation = monitor.cancellation)
        try {
            broker.bindSession("actual-session", "turn-1")
            val cap = capability(broker)
            val first = broker.beginRequest(1, cap, body())
            val firstReceiver = backend.receiver!!
            backend.headers(); backend.subscribe(); backend.emit(completed(1)); backend.complete()
            assertNotNull(first.nextChunk())
            val completedRecord = broker.snapshot().requests.single()
            assertEquals(AcpProviderTerminalKind.COMPLETED, completedRecord.terminal)
            assertTrue(exchangeRecorded(first))
            val second = broker.beginRequest(2, cap, body())
            backend.headers(); backend.subscribe()

            val afterMonitor = observeIdleMonitor(broker, first, bounds.idleTimeout, monitor)
            assertFalse(afterMonitor.revoked)
            assertEquals(listOf(completedRecord), afterMonitor.requests)
            assertNull(first.nextChunk())
            firstReceiver.failed(); firstReceiver.timedOut(); firstReceiver.complete(); first.cancel()
            assertFalse(broker.snapshot().revoked)
            assertFalse(backend.cancelled)
            assertFalse(backend.ownerCancelled)
            assertFalse(backend.subscriptionCancelled)
            backend.emit(completed(1)); backend.complete()
            assertNotNull(second.nextChunk())
            assertEquals(listOf(AcpProviderTerminalKind.COMPLETED, AcpProviderTerminalKind.COMPLETED), broker.snapshot().requests.map { it.terminal })
            assertEquals(completedRecord, broker.snapshot().requests.first())
            assertEquals(2, backend.starts)
            broker.close()
            assertNull(first.nextChunk()); assertNull(second.nextChunk())
            assertEquals(completedRecord, broker.snapshot().requests.first())
        } finally { broker.close() }
    }

    @Test
    fun `released completed exchange cannot revoke the next request through stale callbacks`() {
        val backend = FixtureBackend()
        val broker = open(backend, inputTokens = 2)
        try {
            broker.bindSession("actual-session", "turn-1")
            val cap = capability(broker)
            val first = broker.beginRequest(1, cap, body())
            val firstReceiver = backend.receiver!!
            backend.headers(); backend.subscribe(); backend.emit(completed(1)); backend.complete()
            assertNotNull(first.nextChunk())
            val second = broker.beginRequest(2, cap, body())
            firstReceiver.failed()
            first.cancel()
            assertFalse(broker.snapshot().revoked)
            assertFalse(backend.cancelled)
            assertNull(first.nextChunk())
            backend.headers(); backend.subscribe(); backend.emit(completed(1)); backend.complete()
            assertNotNull(second.nextChunk())
            assertEquals(listOf(AcpProviderTerminalKind.COMPLETED, AcpProviderTerminalKind.COMPLETED), broker.snapshot().requests.map { it.terminal })
            assertKind(AcpProviderTerminalKind.RESOURCE_EXHAUSTED) { broker.beginRequest(3, cap, body()) }
            assertEquals(2, backend.starts)
        } finally { broker.close() }
    }

    @Test
    fun `multi chunk completion freezes only after its final EOF validated chunk is delivered`() {
        for (cancelBeforeLast in listOf(true, false)) {
            val backend = FixtureBackend()
            val broker = open(backend, policy = policy(AcpProviderTransportBounds(maximumChunkBytes = 256, maximumQueuedChunks = 2)))
            try {
                broker.bindSession("actual-session", "turn-1")
                val exchange = broker.beginRequest(1, capability(broker), body())
                backend.headers(); backend.subscribe()
                // The suffix is a credential prefix, so this entire delta stays quarantined
                // until actual upstream EOF disproves continuation of the synthetic secret.
                backend.emit(delta("x".repeat(70) + "s")); backend.emit(completed(3)); backend.complete()
                assertEquals(256, exchange.nextChunk()!!.size)
                assertTrue(broker.snapshot().requests.isEmpty(), "one undelivered chunk cannot be recorded as delivered completion")
                if (cancelBeforeLast) {
                    exchange.cancel()
                    assertKind(AcpProviderTerminalKind.CANCELLED) { exchange.nextChunk() }
                    assertEquals(AcpProviderTerminalKind.CANCELLED, broker.snapshot().requests.single().terminal)
                } else {
                    val last = exchange.nextChunk()!!
                    assertTrue(last.size in 1..255)
                    assertEquals(AcpProviderTerminalKind.COMPLETED, broker.snapshot().requests.single().terminal)
                    broker.close()
                    assertNull(exchange.nextChunk())
                    assertEquals(AcpProviderTerminalKind.COMPLETED, broker.snapshot().requests.single().terminal)
                }
            } finally { broker.close() }
        }
    }

    @Test
    fun `disabled policy missing credentials and excessive enclosing duration create no backend request`() {
        val backend = FixtureBackend()
        assertFailsWith<AcpProviderBrokerFailure> { open(backend, policy = AcpProviderTransportPolicy.DISABLED) }
        assertFailsWith<AcpProviderBrokerFailure> { open(backend, credentials = null) }
        assertFailsWith<IllegalArgumentException> { open(backend, remaining = Duration.ZERO) }
        assertFailsWith<IllegalArgumentException> { open(backend, remaining = Duration.ofSeconds(20)) }
        assertEquals(0, backend.starts)
        assertEquals(0, backend.closes)
    }

    @Test
    fun `routing operation model reasoning and duplicate JSON are refused before dispatch`() {
        for (scenario in 0..7) {
            val backend = FixtureBackend()
            val broker = open(backend)
            try {
                broker.bindSession("actual-session", "turn-1")
                val cap = capability(broker)
                val expected = when (scenario) {
                    2, 6 -> AcpProviderTerminalKind.UNSUPPORTED_MODEL
                    5 -> AcpProviderTerminalKind.MALFORMED_REQUEST
                    else -> AcpProviderTerminalKind.UNSUPPORTED_OPERATION
                }
                assertKind(expected) {
                    when (scenario) {
                        0 -> broker.beginRequest(1, cap, body(), requestedEndpoint = "https://example.invalid/responses")
                        1 -> broker.beginRequest(1, cap, body(), requestedOperation = "MODEL_LIST")
                        2 -> broker.beginRequest(1, cap, body(model = "other-model"))
                        3 -> broker.beginRequest(1, cap, body(effort = "high"))
                        4 -> broker.beginRequest(1, cap, body().decodeToString().dropLast(1).plus(",\"service_tier\":\"priority\"}").toByteArray())
                        5 -> broker.beginRequest(1, cap, body().decodeToString().dropLast(1).plus(",\"model\":\"gpt-6.1-sol\"}").toByteArray())
                        6 -> broker.beginRequest(1, cap, body().decodeToString().replace("\"gpt-6.1-sol\"", "{}").toByteArray())
                        else -> broker.beginRequest(1, cap, body().decodeToString().replace("\"stream\":true", "\"stream\":\"true\"").toByteArray())
                    }
                }
                assertTrue(broker.snapshot().revoked)
                assertEquals(expected, broker.snapshot().admissionDenial!!.terminal)
                assertKind(AcpProviderTerminalKind.REVOKED) { broker.beginRequest(1, cap, body()) }
                assertEquals(0, backend.starts)
                assertTrue(broker.snapshot().requests.isEmpty(), "a denial has no invented wire receipt")
            } finally { broker.close() }
        }
    }

    @Test
    fun `session capability and strict request sequence precede every backend side effect`() {
        for (scenario in 0..4) {
            val backend = FixtureBackend()
            val broker = open(backend)
            val other = open(FixtureBackend())
            try {
                val cap = capability(broker)
                if (scenario != 0) broker.bindSession("actual-session", "turn-1")
                if (scenario >= 3) broker.beginRequest(1, cap, body())
                assertKind(AcpProviderTerminalKind.REVOKED) {
                    when (scenario) {
                        0 -> broker.beginRequest(1, cap, body())
                        1 -> broker.beginRequest(1, capability(other), body())
                        2 -> broker.beginRequest(2, cap, body())
                        3 -> broker.beginRequest(1, cap, body())
                        else -> broker.beginRequest(2, cap, body())
                    }
                }
                assertTrue(broker.snapshot().revoked)
                assertEquals(if (scenario >= 3) 1 else 0, backend.starts)
                assertKind(AcpProviderTerminalKind.REVOKED) { broker.beginRequest(1, cap, body()) }
            } finally { broker.close(); other.close() }
        }
    }

    @Test
    fun `declared output budget comes from admitted request and streams obey demand`() {
        val backend = FixtureBackend()
        val broker = open(backend, outputTokens = 5)
        try {
            broker.bindSession("actual-session", "turn-1")
            val exchange = broker.beginRequest(1, capability(broker), body())
            assertEquals(5, Json.parseToJsonElement(backend.lastRequest!!.body.decodeToString()).jsonObject.getValue("max_output_tokens").jsonPrimitive.int)
            backend.headers()
            backend.subscribe()
            assertEquals(1L, backend.demand)
            // '!' cannot continue the token/account prefixes or the random capability hex.
            backend.emit(delta("safe candidate!"))
            assertEquals(0L, backend.demand, "a queued chunk must apply backpressure")
            assertEquals(200, exchange.awaitHeaders().status)
            assertTrue(exchange.nextChunk()!!.decodeToString().contains("safe candidate!"))
            assertEquals(1L, backend.demand)
            backend.emit(completed(3))
            backend.complete()
            assertNotNull(exchange.nextChunk())
            assertNull(exchange.nextChunk())
            val evidence = broker.snapshot()
            assertEquals(3L, evidence.outputTokens)
            assertEquals(AcpProviderTerminalKind.COMPLETED, evidence.requests.single().terminal)
            assertNotEquals(evidence.requests.single().admittedBodySha256, evidence.requests.single().wireBodySha256)
            assertFalse(evidence.adapterQualified)
            assertFalse(evidence.providerCostCancellationProven)
        } finally { broker.close() }
    }

    @Test
    fun `capability prefix quarantine requests one bounded item until disproof or secret refusal`() {
        for (completeSecret in listOf(false, true)) {
            val backend = FixtureBackend()
            val broker = open(backend, policy = policy(AcpProviderTransportBounds(maximumChunkBytes = 256, maximumQueuedChunks = 1)))
            try {
                broker.bindSession("actual-session", "turn-1")
                val cap = capability(broker)
                val capabilityText = cap.joinToString("") { "%02x".format(it) }
                val exchange = broker.beginRequest(1, cap, body())
                backend.headers(); backend.subscribe()
                val heldEvent = delta(capabilityText.take(32))
                backend.emit(heldEvent)
                assertEquals(1L, backend.demand, "held prefix permits exactly one further bounded item")
                if (completeSecret) {
                    backend.emit(delta(capabilityText.drop(32)))
                    assertKind(AcpProviderTerminalKind.SECRET_EXPOSURE) { exchange.nextChunk() }
                    assertEquals(0L, backend.demand)
                    assertTrue(backend.cancelled)
                    assertEquals(AcpProviderTerminalKind.SECRET_EXPOSURE, broker.snapshot().requests.single().terminal)
                } else {
                    val disproof = delta("!")
                    backend.emit(disproof)
                    assertEquals(0L, backend.demand, "disproved prefix is now queued and applies backpressure")
                    assertContentEquals(heldEvent + disproof, exchange.nextChunk())
                    assertEquals(1L, backend.demand)
                    backend.emit(completed(1)); backend.complete()
                    assertNotNull(exchange.nextChunk()); assertNull(exchange.nextChunk())
                    assertEquals(AcpProviderTerminalKind.COMPLETED, broker.snapshot().requests.single().terminal)
                }
                assertEquals(1, backend.starts, "quarantine progress must not dispatch another provider request")
            } finally { broker.close() }
        }
    }

    @Test
    fun `all capability first nibbles distinguish quarantined prefixes from publishable chunks`() {
        for (nibble in "0123456789abcdef") {
            val syntheticCapability = "$nibble" + "0".repeat(63)
            fun stream() = AcpProviderResponseStream(
                AcpProviderTransportBounds(maximumChunkBytes = 256, maximumQueuedChunks = 1),
                listOf(TEST_TOKEN.toByteArray(), "fixture_account".toByteArray(), syntheticCapability.toByteArray()),
                maximumRemainingOutputTokens = 5,
            )
            for (publishable in listOf(false, true)) {
                val parser = stream()
                val event = delta(if (publishable) "safe candidate!" else "safe candidate")
                val held = !publishable && nibble == 'e'
                val firstRelease = parser.accept(event)
                if (held) assertTrue(firstRelease.isEmpty()) else assertContentEquals(event, firstRelease.single())
                val disproof = delta("!")
                val afterDisproof = parser.accept(disproof)
                if (held) {
                    assertEquals(2, afterDisproof.size)
                    assertContentEquals(event, afterDisproof[0])
                    assertContentEquals(disproof, afterDisproof[1])
                } else assertContentEquals(disproof, afterDisproof.single())
                assertTrue(parser.accept(completed(1)).isEmpty())
                parser.finish()
                assertEquals(1, parser.drainFinished().size)
            }
            val refusing = stream()
            assertTrue(refusing.accept(delta(syntheticCapability.take(32))).isEmpty())
            assertEquals(AcpProviderTerminalKind.SECRET_EXPOSURE,
                assertFailsWith<AcpProviderStreamFailure> { refusing.accept(delta(syntheticCapability.drop(32))) }.kind)
        }
    }

    @Test
    fun `response token quota is invocation cumulative`() {
        val backend = FixtureBackend()
        val broker = open(backend, outputTokens = 5)
        try {
            broker.bindSession("actual-session", "turn-1")
            val cap = capability(broker)
            var exchange = broker.beginRequest(1, cap, body())
            backend.headers(); backend.subscribe(); backend.emit(completed(3)); backend.complete()
            assertNotNull(exchange.nextChunk()); assertNull(exchange.nextChunk())
            exchange = broker.beginRequest(2, cap, body())
            assertEquals(2, Json.parseToJsonElement(backend.lastRequest!!.body.decodeToString()).jsonObject.getValue("max_output_tokens").jsonPrimitive.int)
            backend.headers(); backend.subscribe(); backend.emit(completed(3)); backend.complete()
            assertKind(AcpProviderTerminalKind.RESOURCE_EXHAUSTED) { exchange.nextChunk() }
            assertTrue(broker.snapshot().revoked)
        } finally { broker.close() }
    }

    @Test
    fun `wire request byte budget does not reset after completed exchange`() {
        val backend = FixtureBackend()
        val broker = open(backend, policy = policy(AcpProviderTransportBounds(maximumRequestBytes = 256)))
        try {
            broker.bindSession("actual-session", "turn-1")
            val cap = capability(broker)
            val first = broker.beginRequest(1, cap, body())
            backend.headers(); backend.subscribe(); backend.emit(completed(1)); backend.complete()
            assertNotNull(first.nextChunk()); assertNull(first.nextChunk())
            assertKind(AcpProviderTerminalKind.RESOURCE_EXHAUSTED) { broker.beginRequest(2, cap, body()) }
            assertEquals(1, backend.starts)
        } finally { broker.close() }
    }

    @Test
    fun `response byte budget does not reset after completed exchange`() {
        val backend = FixtureBackend()
        val broker = open(backend, policy = policy(AcpProviderTransportBounds(maximumResponseBytes = 300, maximumChunkBytes = 256)))
        try {
            broker.bindSession("actual-session", "turn-1")
            val cap = capability(broker)
            var observed = 0
            var sequence = 1L
            while (observed + completed(1).size <= 300) {
                val exchange = broker.beginRequest(sequence++, cap, body())
                backend.headers(); backend.subscribe(); backend.emit(completed(1)); backend.complete()
                assertNotNull(exchange.nextChunk()); assertNull(exchange.nextChunk())
                observed += completed(1).size
            }
            val refused = broker.beginRequest(sequence, cap, body())
            backend.headers(); backend.subscribe(); backend.emit(completed(1))
            assertKind(AcpProviderTerminalKind.RESOURCE_EXHAUSTED) { refused.nextChunk() }
            assertTrue(broker.snapshot().revoked)
        } finally { broker.close() }
    }

    @Test
    fun `malformed Unicode session identities are refused without replacement hashing`() {
        val backend = FixtureBackend()
        val broker = open(backend)
        try {
            val failure = assertFailsWith<IllegalArgumentException> { broker.bindSession("bad\uD800", "turn-1") }
            assertNull(failure.cause)
            assertFalse(failure.message!!.contains("bad"))
            assertFailsWith<IllegalArgumentException> { broker.bindSession("session", "bad\uDC00") }
            broker.bindSession("valid-session", "valid-turn")
            assertEquals(0, backend.starts)
        } finally { broker.close() }
    }

    @Test
    fun `concrete HTTP transport and lifecycle terminate without any provider request`() {
        val request = AgentExecutionRequest("construct and close host owner only", listOf(AgentWorkspaceRoot("fixture", Path.of(System.getProperty("user.dir")))),
            accessPolicy = AgentAccessPolicy(emptyList()), limits = AgentExecutionLimits(wallClockTimeout = Duration.ofSeconds(10)))
        val broker = AcpProviderBroker.openForProtectedQualification(policy(), request, Duration.ofSeconds(2),
            AcpProviderCredentialMaterial.cachedChatGpt(TEST_TOKEN, "fixture_account"))
        assertEquals(AcpProviderBrokerCleanup.NOT_ATTEMPTED, broker.snapshot().cleanup)
        broker.close()
        assertEquals(AcpProviderBrokerCleanup.VERIFIED, broker.snapshot().cleanup)
        assertEquals(0L, broker.snapshot().wireRequestBytes)
        assertTrue(broker.snapshot().requests.isEmpty())
        assertFalse(broker.snapshot().adapterQualified)
    }

    @Test
    fun `raw upstream authentication error body is never exposed or retained`() {
        val backend = FixtureBackend()
        val broker = open(backend)
        try {
            broker.bindSession("actual-session", "turn-1")
            val exchange = broker.beginRequest(1, capability(broker), body())
            backend.receiver!!.headers(401, mapOf("content-type" to listOf("application/json"), "x-secret" to listOf(TEST_TOKEN)))
            backend.receiver!!.bytes(listOf(ByteBuffer.wrap(("error=" + TEST_TOKEN).toByteArray())))
            val failure = assertFailsWith<AcpProviderBrokerFailure> { exchange.awaitHeaders() }
            assertEquals(AcpProviderTerminalKind.AUTHENTICATION, failure.kind)
            assertFalse(failure.toString().contains(TEST_TOKEN))
            assertNull(failure.cause)
            assertEquals(0L, broker.snapshot().responseBytes)
            assertEquals(AcpProviderTerminalKind.AUTHENTICATION, broker.snapshot().requests.single().terminal)
        } finally { broker.close() }
    }

    @Test
    fun `successful response secret split is refused before any candidate chunk`() {
        val backend = FixtureBackend()
        val broker = open(backend)
        try {
            broker.bindSession("actual-session", "turn-1")
            val exchange = broker.beginRequest(1, capability(broker), body())
            backend.headers(); backend.subscribe()
            backend.emit(delta(TEST_TOKEN.take(8)))
            assertEquals(1L, backend.demand, "quarantined prefix allows one further bounded network item")
            backend.emit(delta(TEST_TOKEN.drop(8)))
            assertKind(AcpProviderTerminalKind.SECRET_EXPOSURE) { exchange.nextChunk() }
            assertTrue(broker.snapshot().revoked)
            assertEquals(AcpProviderTerminalKind.SECRET_EXPOSURE, broker.snapshot().requests.single().terminal)
        } finally { broker.close() }
    }

    @Test
    fun `cancellation revokes stalled consumer and cleanup failure retains owner`() {
        val cancelled = AgentCancellationSource()
        val backend = FixtureBackend(clean = false)
        val broker = open(backend, cancellation = cancelled.cancellation)
        broker.bindSession("actual-session", "turn-1")
        val cap = capability(broker)
        broker.beginRequest(1, cap, body())
        backend.headers(); backend.subscribe()
        cancelled.cancel()
        await { broker.snapshot().revoked }
        assertTrue(backend.cancelled)
        assertEquals(AcpProviderTerminalKind.CANCELLED, broker.snapshot().requests.single().terminal)
        assertFailsWith<AcpProviderBrokerCleanupFailure> { broker.close() }
        assertEquals(AcpProviderBrokerCleanup.UNVERIFIED, broker.snapshot().cleanup)
        assertKind(AcpProviderTerminalKind.REVOKED) { broker.beginRequest(2, cap, body()) }
        val attempts = backend.closes
        backend.clean = true
        assertFailsWith<AcpProviderBrokerCleanupFailure> { broker.close() }
        assertEquals(attempts, backend.closes, "cleanup retry received a fresh backend grace")
        assertEquals(AcpProviderBrokerCleanup.UNVERIFIED, broker.snapshot().cleanup)
    }

    @Test
    fun `deadline and idle expiry revoke without response consumer progress`() {
        val backend = FixtureBackend()
        val bounds = AcpProviderTransportBounds(overallTimeout = Duration.ofMillis(150), idleTimeout = Duration.ofMillis(20), cleanupTimeout = Duration.ofMillis(100))
        val broker = open(backend, policy = policy(bounds), remaining = Duration.ofMillis(100))
        try {
            broker.bindSession("actual-session", "turn-1")
            broker.beginRequest(1, capability(broker), body())
            backend.headers(); backend.subscribe()
            await { broker.snapshot().revoked }
            assertTrue(backend.cancelled)
            assertEquals(AcpProviderTerminalKind.TIMEOUT, broker.snapshot().requests.single().terminal)
        } finally { broker.close() }
    }

    @Test
    fun `header caps streaming queue overflow and invalid content type refuse publication`() {
        for (scenario in 0..2) {
            val backend = FixtureBackend()
            val broker = open(backend, policy = policy(AcpProviderTransportBounds(maximumQueuedChunks = 1, maximumHeaderBytes = 64)))
            try {
                broker.bindSession("actual-session", "turn-1")
                val exchange = broker.beginRequest(1, capability(broker), body())
                when (scenario) {
                    0 -> backend.receiver!!.headers(200, mapOf("huge" to listOf("x".repeat(65))))
                    1 -> backend.receiver!!.headers(200, mapOf("content-type" to listOf("text/plain")))
                    else -> { backend.headers(); backend.subscribe(); backend.emit(delta("x".repeat(32768)) + delta("y".repeat(32768))) }
                }
                val failure = assertFailsWith<AcpProviderBrokerFailure> { exchange.nextChunk() }
                assertEquals(if (scenario == 1) AcpProviderTerminalKind.MALFORMED_RESPONSE else AcpProviderTerminalKind.RESOURCE_EXHAUSTED, failure.kind)
                assertTrue(broker.snapshot().revoked)
            } finally { broker.close() }
        }
    }

    @Test
    fun `multiple small events in one network batch coalesce without false overflow`() {
        val backend = FixtureBackend()
        val broker = open(backend, policy = policy(AcpProviderTransportBounds(maximumQueuedChunks = 1)))
        try {
            broker.bindSession("actual-session", "turn-1")
            val exchange = broker.beginRequest(1, capability(broker), body())
            backend.headers(); backend.subscribe()
            backend.emit(delta("one") + delta("two") + delta("three") + completed(1))
            assertFalse(broker.snapshot().revoked)
            backend.complete()
            val combined = exchange.nextChunk()!!.decodeToString()
            assertTrue(combined.contains("one") && combined.contains("two") && combined.contains("three") && combined.contains("response.completed"))
            assertNull(exchange.nextChunk())
        } finally { broker.close() }
    }

    private fun assertFixedRevoked(result: Result<Unit>) {
        val failure = assertIs<AcpProviderBrokerFailure>(result.exceptionOrNull())
        assertEquals(AcpProviderTerminalKind.REVOKED, failure.kind)
        assertEquals("ACP provider broker: REVOKED", failure.message)
        assertNull(failure.cause)
    }

    private fun assertAuthorityRevoked(broker: AcpProviderBroker) {
        assertTrue(broker.snapshot().revoked)
        val value = AcpProviderBroker::class.java.getDeclaredField("capability").let { it.isAccessible = true; it.get(broker) as ByteArray }
        assertTrue(value.all { it == 0.toByte() }, "revoked capability storage must be zeroed")
        assertKind(AcpProviderTerminalKind.REVOKED) { broker.channelSetupPayload() }
    }

    private fun bindingHashes(broker: AcpProviderBroker): Pair<Any?, Any?> =
        listOf("sessionSha256", "turnSha256").map { name ->
            AcpProviderBroker::class.java.getDeclaredField(name).let { it.isAccessible = true; it.get(broker) }
        }.let { it[0] to it[1] }

    private fun inputMessage(text: String, native: Boolean = false): String = if (native)
        """{"type":"message","role":"user","content":[{"type":"input_text","text":$text}]}"""
    else """{"role":"user","content":$text}"""

    private fun rawInputRequest(input: String): ByteArray {
        val fixture = "\"input\":[{\"role\":\"user\",\"content\":\"synthetic fixture\"}]"
        val original = body().decodeToString()
        check(original.contains(fixture)) { "input fixture is unavailable" }
        return original.replace(fixture, "\"input\":$input").toByteArray()
    }

    private fun assertInputRefused(input: String, kind: AcpProviderTerminalKind = AcpProviderTerminalKind.UNSUPPORTED_OPERATION,
        selectedPolicy: AcpProviderTransportPolicy = policy()) = assertInputRequestRefused(rawInputRequest(input), kind, selectedPolicy)

    private fun assertInputRequestRefused(request: ByteArray, kind: AcpProviderTerminalKind, selectedPolicy: AcpProviderTransportPolicy) {
        val backend = FixtureBackend()
        val broker = open(backend, policy = selectedPolicy)
        try {
            broker.bindSession("actual-session", "turn-1")
            val result = runCatching { broker.beginRequest(1, capability(broker), request) }
            assertEquals(0, backend.starts, "unsupported mandatory input reached the fixture backend")
            val failure = assertIs<AcpProviderBrokerFailure>(result.exceptionOrNull())
            assertEquals(kind, failure.kind)
            assertNull(failure.cause)
            assertEquals("ACP provider broker: ${kind.name}", failure.message)
            assertNull(backend.lastRequest)
            val evidence = broker.snapshot()
            assertTrue(evidence.revoked)
            assertEquals(kind, evidence.admissionDenial!!.terminal)
            assertTrue(evidence.requests.isEmpty())
            assertEquals(0L, evidence.wireRequestBytes)
            assertEquals(0L, evidence.outputTokens)
        } finally { broker.close() }
    }

    private fun assertCompletedQueueIdleExpiry(consumedChunks: Int) {
        val backend = FixtureBackend()
        val monitor = LifecycleObservation()
        val bounds = AcpProviderTransportBounds(maximumChunkBytes = 256, maximumQueuedChunks = 2)
        val broker = open(backend, policy = policy(bounds), cancellation = monitor.cancellation)
        try {
            broker.bindSession("actual-session", "turn-1")
            val cap = capability(broker)
            val exchange = broker.beginRequest(1, cap, body())
            val receiver = backend.receiver!!
            backend.headers(); backend.subscribe()
            // This known synthetic credential prefix stays quarantined until upstream EOF,
            // producing exactly two queued chunks without depending on the random capability.
            backend.emit(delta("x".repeat(70) + "s")); backend.emit(completed(3)); backend.complete()
            assertEquals(2, exchangeQueueSize(exchange))
            if (consumedChunks == 1) assertEquals(256, exchange.nextChunk()!!.size)
            assertEquals(2 - consumedChunks, exchangeQueueSize(exchange))
            assertEquals(AcpProviderTerminalKind.COMPLETED, exchange.terminal)
            assertFalse(exchangeRecorded(exchange))
            assertTrue(broker.snapshot().requests.isEmpty())

            val afterMonitor = observeIdleMonitor(broker, exchange, bounds.idleTimeout, monitor)
            assertTrue(afterMonitor.revoked, "expired completed queue survived the real idle monitor: queued=${exchangeQueueSize(exchange)}, terminal=${exchange.terminal}, recorded=${exchangeRecorded(exchange)}, revoked=${afterMonitor.revoked}")
            val timeoutRecord = afterMonitor.requests.single()
            assertEquals(AcpProviderTerminalKind.TIMEOUT, timeoutRecord.terminal)
            assertEquals(3, timeoutRecord.outputTokens)
            assertEquals(3, timeoutRecord.admittedOutputTokens)
            assertEquals(1, timeoutRecord.inputTokens)
            assertEquals(3L, afterMonitor.outputTokens)
            assertEquals(0, exchangeQueueSize(exchange))
            assertTrue(exchangeRecorded(exchange))
            assertNull(AcpProviderBroker::class.java.getDeclaredField("active").let { it.isAccessible = true; it.get(broker) })
            assertTrue(backend.ownerCancelled)
            assertTrue(backend.subscriptionCancelled)
            assertEquals(AcpProviderBrokerCleanup.NOT_ATTEMPTED, afterMonitor.cleanup)
            assertEquals(0, backend.closes)
            assertKind(AcpProviderTerminalKind.TIMEOUT) { exchange.nextChunk() }
            receiver.complete(); receiver.failed(); receiver.timedOut(); exchange.cancel()
            assertEquals(listOf(timeoutRecord), broker.snapshot().requests)
            assertKind(AcpProviderTerminalKind.REVOKED) { broker.beginRequest(2, cap, body()) }
            assertEquals(1, backend.starts)
            backend.clean = false
            assertFailsWith<AcpProviderBrokerCleanupFailure> { broker.close() }
            assertEquals(AcpProviderBrokerCleanup.UNVERIFIED, broker.snapshot().cleanup)
            assertEquals(listOf(timeoutRecord), broker.snapshot().requests)
            assertKind(AcpProviderTerminalKind.REVOKED) { broker.beginRequest(2, cap, body()) }
            backend.clean = true
            assertFailsWith<AcpProviderBrokerCleanupFailure> { broker.close() }
            assertEquals(AcpProviderBrokerCleanup.UNVERIFIED, broker.snapshot().cleanup)
            assertEquals(listOf(timeoutRecord), broker.snapshot().requests)
            assertKind(AcpProviderTerminalKind.REVOKED) { broker.beginRequest(2, cap, body()) }
            assertKind(AcpProviderTerminalKind.TIMEOUT) { exchange.nextChunk() }
            assertEquals(1, backend.starts)
        } finally { backend.clean = true; runCatching { broker.close() } }
    }

    /** Observe the real periodic owner after aging only its existing activity timestamp. */
    private fun observeIdleMonitor(
        broker: AcpProviderBroker,
        exchange: AcpProviderBroker.AcpProviderBrokerExchange,
        idleTimeout: Duration,
        monitor: LifecycleObservation,
    ): AcpProviderBrokerSnapshot {
        val lock = AcpProviderBroker::class.java.getDeclaredField("lock").let {
            it.isAccessible = true; it.get(broker) as java.util.concurrent.locks.ReentrantLock
        }
        lock.lock()
        try {
            exchange.javaClass.getDeclaredField("lastActivityNanos").also { it.isAccessible = true }
                .setLong(exchange, System.nanoTime() - idleTimeout.toNanos() - 1)
            monitor.armed.set(true)
        } finally { lock.unlock() }
        assertTrue(monitor.observed.await(1, TimeUnit.SECONDS), "real lifecycle monitor did not run")
        // The callback signals inside checkActive; reacquiring the same owner lock proves the
        // subsequent checkIdle finished. No consumer operation is allowed to drive expiry.
        lock.lock()
        try {
            monitor.armed.set(false)
            assertEquals("decomp-acp-provider-lifecycle", monitor.firstThread.get())
            val started = AcpProviderBroker::class.java.getDeclaredField("startedNanos").let { it.isAccessible = true; it.getLong(broker) }
            val allowed = AcpProviderBroker::class.java.getDeclaredField("allowedNanos").let { it.isAccessible = true; it.getLong(broker) }
            assertTrue(System.nanoTime() - started < allowed, "overall deadline must remain live during idle observation")
            return broker.snapshot()
        } finally { lock.unlock() }
    }

    private fun exchangeQueueSize(exchange: AcpProviderBroker.AcpProviderBrokerExchange): Int =
        exchange.javaClass.getDeclaredField("queue").let { it.isAccessible = true; (it.get(exchange) as Collection<*>).size }

    private fun exchangeRecorded(exchange: AcpProviderBroker.AcpProviderBrokerExchange): Boolean =
        exchange.javaClass.getDeclaredField("recorded").let { it.isAccessible = true; it.getBoolean(exchange) }

    private class LifecycleObservation {
        val armed = AtomicBoolean(false)
        val observed = CountDownLatch(1)
        val firstThread = java.util.concurrent.atomic.AtomicReference<String>()
        val cancellation = AgentCancellation {
            if (armed.get()) { firstThread.compareAndSet(null, Thread.currentThread().name); observed.countDown() }
            false
        }
    }

    private fun assertOptionalAccepted(fields: String) {
        val backend = FixtureBackend()
        val broker = open(backend, outputTokens = 32)
        try {
            broker.bindSession("actual-session", "turn-1")
            val request = optionalRequest(fields)
            val exchange = broker.beginRequest(1, capability(broker), request)
            assertEquals(1, backend.starts)
            val expected = kotlinx.serialization.json.JsonObject(Json.parseToJsonElement(request.decodeToString()).jsonObject +
                ("max_output_tokens" to kotlinx.serialization.json.JsonPrimitive(32)))
            assertEquals(expected, Json.parseToJsonElement(backend.lastRequest!!.body.decodeToString()))
            backend.headers(); backend.subscribe(); backend.emit(completed(1)); backend.complete()
            assertNotNull(exchange.nextChunk()); assertNull(exchange.nextChunk())
            assertEquals(AcpProviderTerminalKind.COMPLETED, broker.snapshot().requests.single().terminal)
            assertEquals(1, backend.starts)
        } finally { broker.close() }
    }

    private fun assertOptionalRefused(fields: String) {
        val backend = FixtureBackend()
        val broker = open(backend)
        try {
            broker.bindSession("actual-session", "turn-1")
            val result = runCatching { broker.beginRequest(1, capability(broker), optionalRequest(fields)) }
            assertEquals(0, backend.starts, "unsupported optional request reached the fixture backend: $fields")
            val failure = assertIs<AcpProviderBrokerFailure>(result.exceptionOrNull(), fields)
            assertEquals(AcpProviderTerminalKind.UNSUPPORTED_OPERATION, failure.kind, fields)
            assertNull(failure.cause)
            assertEquals("ACP provider broker: UNSUPPORTED_OPERATION", failure.message)
            assertNull(backend.lastRequest)
            val evidence = broker.snapshot()
            assertTrue(evidence.revoked)
            assertTrue(evidence.requests.isEmpty())
            assertEquals(AcpProviderTerminalKind.UNSUPPORTED_OPERATION, evidence.admissionDenial!!.terminal)
            assertEquals(0L, evidence.wireRequestBytes)
            assertEquals(0L, evidence.outputTokens)
        } finally { broker.close() }
    }

    private fun optionalRequest(fields: String): ByteArray = kotlinx.serialization.json.JsonObject(
        Json.parseToJsonElement(body().decodeToString()).jsonObject + Json.parseToJsonElement("{$fields}").jsonObject,
    ).toString().toByteArray()

    private fun parameterSchema(properties: String = "{}", required: String = "[]"): String =
        """{"type":"object","properties":$properties,"required":$required,"additionalProperties":false}"""

    private fun functionTool(name: String = "fixture", schema: String = parameterSchema(), suffix: String = ""): String =
        """{"type":"function","name":"$name","parameters":$schema$suffix}"""

    private fun open(
        backend: FixtureBackend,
        policy: AcpProviderTransportPolicy = policy(),
        credentials: AcpProviderCredentialMaterial? = AcpProviderCredentialMaterial.cachedChatGpt(TEST_TOKEN, "fixture_account"),
        remaining: Duration = Duration.ofSeconds(2),
        outputTokens: Long? = null,
        inputTokens: Long? = null,
        cancellation: AgentCancellation = AgentCancellation.NONE,
    ): AcpProviderBroker = AcpProviderBroker.openForTesting(
        policy,
        AgentExecutionRequest("credential-free broker control", listOf(AgentWorkspaceRoot("fixture", Path.of(System.getProperty("user.dir")))),
            accessPolicy = AgentAccessPolicy(emptyList()), limits = AgentExecutionLimits(wallClockTimeout = Duration.ofSeconds(10), maxOutputTokens = outputTokens, maxInputTokens = inputTokens), cancellation = cancellation),
        remaining, credentials, backend,
    )

    private fun policy(bounds: AcpProviderTransportBounds = AcpProviderTransportBounds()): AcpProviderTransportPolicy.Approved =
        AcpProviderTransportPolicy.issueApproved(URI("https://chatgpt.com/backend-api/codex/responses"), "gpt-6.1-sol", AcpProviderReasoning.LOW, bounds)

    private fun capability(broker: AcpProviderBroker): ByteArray = AcpProviderBrokerProtocol.decodeChannelSetupPayload(broker.channelSetupPayload()).capability
    private fun body(model: String = "gpt-6.1-sol", effort: String = "low"): ByteArray =
        """{"model":"$model","input":[{"role":"user","content":"synthetic fixture"}],"reasoning":{"effort":"$effort"},"store":false,"stream":true}""".toByteArray()
    private fun requestString(value: String, escapeMode: Int): String = if (escapeMode != 0)
        "\"" + value.mapIndexed { index, character ->
            if (escapeMode == 1 || index % 2 == 0) "\\u%04x".format(character.code) else character.toString()
        }.joinToString("") + "\""
    else kotlinx.serialization.json.JsonPrimitive(value).toString()
    private fun delta(text: String): ByteArray = ("event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":" + kotlinx.serialization.json.JsonPrimitive(text).toString() + "}\n\n").toByteArray()
    private fun completed(tokens: Int): ByteArray = """event: response.completed
data: {"type":"response.completed","response":{"status":"completed","usage":{"input_tokens":1,"output_tokens":$tokens}}}

""".toByteArray()
    private fun assertKind(kind: AcpProviderTerminalKind, action: () -> Unit) = assertEquals(kind, assertFailsWith<AcpProviderBrokerFailure>(block = action).kind)
    private fun await(condition: () -> Boolean) {
        val stop = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
        while (!condition() && System.nanoTime() < stop) Thread.sleep(2)
        assertTrue(condition(), "bounded lifecycle control did not finish")
    }

    private class FixtureBackend(var clean: Boolean = true, var interruptCleanup: Boolean = false) : AcpProviderBrokerTestBackend {
        var starts = 0
        var closes = 0
        @Volatile var cancelled = false
        var ownerCancelled = false
        var subscriptionCancelled = false
        var receiver: AcpProviderBackendReceiver? = null
        var lastRequest: AcpProviderBackendRequest? = null
        var demand = 0L
        override fun start(request: AcpProviderBackendRequest, receiver: AcpProviderBackendReceiver): AcpProviderBackendRequestOwner {
            starts++; this.receiver = receiver; lastRequest = request; cancelled = false; ownerCancelled = false; subscriptionCancelled = false; demand = 0
            return object : AcpProviderBackendRequestOwner { override fun cancel() { cancelled = true; ownerCancelled = true } }
        }
        override fun closeWithin(timeout: Duration): Boolean {
            closes++
            if (interruptCleanup) throw InterruptedException("synthetic cleanup interruption")
            return clean
        }
        fun headers() = receiver!!.headers(200, mapOf("content-type" to listOf("text/event-stream")))
        fun subscribe() = receiver!!.subscribe(object : Flow.Subscription {
            override fun request(n: Long) { demand += n }
            override fun cancel() { cancelled = true; subscriptionCancelled = true }
        })
        fun emit(bytes: ByteArray) { check(demand > 0); demand--; receiver!!.bytes(listOf(ByteBuffer.wrap(bytes))) }
        fun complete() = receiver!!.complete()
    }

    private companion object { const val TEST_TOKEN = "synthetic-provider-secret-canary" }
}
