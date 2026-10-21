package decompengine.project

import decompengine.agent.AgentExecutionException
import decompengine.agent.AgentFailure
import decompengine.agent.AgentFailureKind
import decompengine.repair.RepairBudgetExceededException
import decompengine.repair.RepairValidationFailureKind
import java.io.IOException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class GeneratedCValidationFailureRecordTest {
    private fun record() = GeneratedCValidationFailureRecord(
        receiptSha256 = "1".repeat(64), sourceRevisionSha256 = "2".repeat(64),
        profileSha256 = "3".repeat(64), indexSha256 = "4".repeat(64),
        regressionCorpusSha256 = "5".repeat(64), runtimeSha256 = "6".repeat(64),
        classification = RepairValidationFailureKind.RESOURCE_EXHAUSTED,
        reason = GeneratedCValidationFailureReason.RESOURCE_EXHAUSTED,
        phase = GeneratedCValidationFailurePhase.SOURCE_PREPARATION, inputCount = 3,
    )

    @Test
    fun `diagnostic binds exact receipt source profile corpus and runtime without validation authority`() {
        val document = Json.parseToJsonElement(record().encode().toString(Charsets.UTF_8)).jsonObject
        assertEquals(setOf("schemaVersion", "kind", "authority", "outcome", "receiptSha256",
            "sourceRevisionSha256", "profileSha256", "indexSha256", "regressionCorpusSha256", "runtimeSha256",
            "classification", "reason", "phase", "inputCount", "inputIndex"), document.keys)
        assertEquals(1, document.getValue("schemaVersion").jsonPrimitive.int)
        assertEquals("producer-diagnostic", document.getValue("authority").jsonPrimitive.content)
        assertEquals("failed", document.getValue("outcome").jsonPrimitive.content)
        listOf("receiptSha256", "sourceRevisionSha256", "profileSha256", "indexSha256",
            "regressionCorpusSha256", "runtimeSha256").forEachIndexed { index, key ->
            assertEquals((index + 1).toString().repeat(64), document.getValue(key).jsonPrimitive.content)
        }
        assertEquals(JsonNull, document.getValue("inputIndex"))
        assertFalse("cleanupVerified" in document || "accepted" in document)
    }

    @Test
    fun `enclosing deadline and agent timeout stay distinct from other resource exhaustion`() {
        val failures = listOf(GeneratedCValidationTimeoutException("private deadline text"),
            AgentExecutionException(AgentFailure(AgentFailureKind.TIMEOUT, "private provider text")))
        failures.forEach { failure ->
            assertEquals(GeneratedCValidationFailureReason.TIMEOUT,
                GeneratedCValidationFailureReason.from(RepairValidationFailureKind.RESOURCE_EXHAUSTED, failure))
        }
        listOf(RepairBudgetExceededException("output bound"),
            AgentExecutionException(AgentFailure(AgentFailureKind.RESOURCE_EXHAUSTED, "provider limit"))).forEach { failure ->
            assertEquals(GeneratedCValidationFailureReason.RESOURCE_EXHAUSTED,
                GeneratedCValidationFailureReason.from(RepairValidationFailureKind.RESOURCE_EXHAUSTED, failure))
        }
    }

    @Test
    fun `cleanup cancellation and generic failure retain established primary classification priority`() {
        val timeout = GeneratedCValidationTimeoutException("private timeout")
        listOf(RepairValidationFailureKind.CLEANUP_UNVERIFIED, RepairValidationFailureKind.CANCELLED,
            RepairValidationFailureKind.VALIDATION_FAILED).forEach { kind ->
            val reason = GeneratedCValidationFailureReason.from(kind, timeout)
            assertEquals(kind, reason.classification)
            val document = Json.parseToJsonElement(record().copy(classification = kind,
                reason = reason).encode().toString(Charsets.UTF_8)).jsonObject
            assertEquals(kind.name.lowercase().replace('_', '-'), document.getValue("reason").jsonPrimitive.content)
        }
    }

    @Test
    fun `raw exception peer messages host paths and commands never enter diagnostic fields`() {
        val privateText = "/private/credentials token=secret peer-command"
        val failure = AgentExecutionException(AgentFailure(AgentFailureKind.TIMEOUT, privateText))
        val text = record().copy(reason = GeneratedCValidationFailureReason.from(
            RepairValidationFailureKind.RESOURCE_EXHAUSTED, failure)).encode().toString(Charsets.UTF_8)
        assertFalse(text.contains(privateText))
        assertFalse(text.contains("credentials") || text.contains("secret") || text.contains("peer-command"))
        assertEquals("timeout", Json.parseToJsonElement(text).jsonObject.getValue("reason").jsonPrimitive.content)
    }

    @Test
    fun `unknown I O failure does not invent timeout process launch or cleanup success`() {
        val reason = GeneratedCValidationFailureReason.from(RepairValidationFailureKind.VALIDATION_FAILED,
            IOException("unknown launch and cleanup state"))
        val document = Json.parseToJsonElement(record().copy(classification = RepairValidationFailureKind.VALIDATION_FAILED,
            reason = reason).encode().toString(Charsets.UTF_8)).jsonObject
        assertEquals("validation-failed", document.getValue("reason").jsonPrimitive.content)
        assertFalse("processStarted" in document || "processStopped" in document || "cleanupVerified" in document)
    }

    @Test
    fun `case locator identifies first and final corpus positions without retaining input bytes`() {
        for (index in listOf(0, 2)) {
            val document = Json.parseToJsonElement(record().copy(
                phase = GeneratedCValidationFailurePhase.ORIGINAL_OPERATION, inputIndex = index,
            ).encode().toString(Charsets.UTF_8)).jsonObject
            assertEquals(index, document.getValue("inputIndex").jsonPrimitive.int)
            assertEquals(3, document.getValue("inputCount").jsonPrimitive.int)
            assertFalse("inputId" in document || "args" in document || "stdin" in document || "command" in document)
        }
        val empty = Json.parseToJsonElement(record().copy(inputCount = 0).encode().toString(Charsets.UTF_8)).jsonObject
        assertEquals(0, empty.getValue("inputCount").jsonPrimitive.int)
        assertEquals(JsonNull, empty.getValue("inputIndex"))
    }

    @Test
    fun `malformed commitments are rejected for every binding field`() {
        for (bad in listOf("A".repeat(64), "a".repeat(63), "a".repeat(65), "a".repeat(63) + 10.toChar())) {
            assertFailsWith<IllegalArgumentException> { record().copy(receiptSha256 = bad) }
            assertFailsWith<IllegalArgumentException> { record().copy(sourceRevisionSha256 = bad) }
            assertFailsWith<IllegalArgumentException> { record().copy(profileSha256 = bad) }
            assertFailsWith<IllegalArgumentException> { record().copy(indexSha256 = bad) }
            assertFailsWith<IllegalArgumentException> { record().copy(regressionCorpusSha256 = bad) }
            assertFailsWith<IllegalArgumentException> { record().copy(runtimeSha256 = bad) }
        }
    }

    @Test
    fun `invalid or non case locators and conflicting classifications are rejected`() {
        assertFailsWith<IllegalArgumentException> { record().copy(inputCount = -1) }
        assertFailsWith<IllegalArgumentException> { record().copy(inputIndex = 0) }
        for (index in listOf(-1, 3)) {
            assertFailsWith<IllegalArgumentException> {
                record().copy(phase = GeneratedCValidationFailurePhase.REBUILT_OPERATION, inputIndex = index)
            }
        }
        assertFailsWith<IllegalArgumentException> {
            record().copy(classification = RepairValidationFailureKind.CANCELLED)
        }
    }

    @Test
    fun `every operation phase fits the fixed byte bound at maximum integer corpus size`() {
        GeneratedCValidationFailurePhase.entries.forEach { phase ->
            val bytes = record().copy(phase = phase, inputCount = Int.MAX_VALUE,
                inputIndex = if (phase.hasCase) Int.MAX_VALUE - 1 else null).encode()
            assertTrue(bytes.size <= GeneratedCValidationFailureRecord.MAXIMUM_BYTES)
            val document = Json.parseToJsonElement(bytes.toString(Charsets.UTF_8)).jsonObject
            assertEquals(Int.MAX_VALUE, document.getValue("inputCount").jsonPrimitive.int)
            assertEquals(phase.wireName, document.getValue("phase").jsonPrimitive.content)
        }
    }

    @Test
    fun `canonical encoding is deterministic detached and changes with its receipt commitment`() {
        val original = record().encode()
        assertContentEquals(original, record().encode())
        assertFalse(original.contentEquals(record().copy(receiptSha256 = "7".repeat(64)).encode()))
        original[0] = 0
        assertEquals('{'.code.toByte(), record().encode().first())
    }

    @Test
    fun `supplement must fit beside the retained primary receipt without increasing its byte ceiling`() {
        val bytes = record().encode()
        assertContentEquals(bytes, record().encodeWithinReceiptBudget(100, 100L + bytes.size))
        assertFailsWith<RepairBudgetExceededException> {
            record().encodeWithinReceiptBudget(100, 99L + bytes.size)
        }
        assertFailsWith<RepairBudgetExceededException> {
            record().encodeWithinReceiptBudget(Long.MAX_VALUE, Long.MAX_VALUE)
        }
        assertFailsWith<IllegalArgumentException> { record().encodeWithinReceiptBudget(-1, 4096) }
        assertFailsWith<IllegalArgumentException> { record().encodeWithinReceiptBudget(0, -1) }
    }
}
