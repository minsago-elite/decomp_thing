package decompengine.project

import decompengine.agent.AgentExecutionException
import decompengine.agent.AgentFailure
import decompengine.agent.AgentFailureKind
import decompengine.repair.RepairBudgetExceededException
import decompengine.repair.RepairValidationFailureKind
import decompengine.repair.RepairValidationInvocation
import decompengine.repair.RepairValidationDiagnosticPublication
import java.io.IOException
import java.nio.file.Path
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
import kotlin.test.assertSame
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

    @Test
    fun `starting a reused label clears its prior supplement even when validation succeeds`() {
        var stored = record().copy(reason = GeneratedCValidationFailureReason.TIMEOUT).encode().toString(Charsets.UTF_8)
        GeneratedCValidationFailurePublication.start { stored = it }
        assertEquals("", stored)
    }

    @Test
    fun `identical receipt with withheld new reason cannot retain the previous timeout diagnostic`() {
        var stored = record().copy(reason = GeneratedCValidationFailureReason.TIMEOUT).encode().toString(Charsets.UTF_8)
        val writes = mutableListOf<String>()
        val publication = GeneratedCValidationFailurePublication.start { stored = it; writes += it }
        assertFailsWith<RepairBudgetExceededException> { publication.publish(record(), 100, 100) }
        assertEquals("", stored)
        assertEquals(listOf(""), writes)
    }

    @Test
    fun `failed atomic publication after reset leaves unavailable data instead of the prior diagnostic`() {
        var stored = "previous diagnostic"
        val problem = IOException("authored publication failure")
        val publication = GeneratedCValidationFailurePublication.start {
            if (it.isEmpty()) stored = it else throw problem
        }
        val thrown = assertFailsWith<IOException> { publication.publish(record(), 100, 4096) }
        assertSame(problem, thrown)
        assertEquals("", stored)
    }

    @Test
    fun `a new diagnostic replaces reset data with the current reason and receipt binding`() {
        val writes = mutableListOf<String>()
        val publication = GeneratedCValidationFailurePublication.start { writes += it }
        publication.publish(record(), 100, 4096)
        assertEquals(2, writes.size)
        assertEquals("", writes.first())
        val current = Json.parseToJsonElement(writes.last()).jsonObject
        assertEquals("resource-exhausted", current.getValue("reason").jsonPrimitive.content)
        assertEquals(record().receiptSha256, current.getValue("receiptSha256").jsonPrimitive.content)
    }

    @Test
    fun `reset failure aborts before the caller can start validation`() {
        var started = false
        val failure = IOException("authored reset failure")
        val thrown = assertFailsWith<IOException> {
            GeneratedCValidationFailurePublication.start { throw failure }.also { started = true }
        }
        assertSame(failure, thrown)
        assertFalse(started)
    }

    @Test
    fun `failure before supplemental publication also leaves the reused label invalidated`() {
        var stored = "previous diagnostic"
        val primary = IllegalStateException("authored validation failure")
        val thrown = assertFailsWith<IllegalStateException> {
            GeneratedCValidationFailurePublication.start { stored = it }
            throw primary
        }
        assertSame(primary, thrown)
        assertEquals("", stored)
    }

    @Test
    fun `snapshot close failure during unwinding records finalization and clears the earlier case`() {
        for (initial in listOf(GeneratedCValidationFailurePhase.BUILD,
            GeneratedCValidationFailurePhase.ORIGINAL_OPERATION, GeneratedCValidationFailurePhase.REBUILT_OPERATION)) {
            for (primary in listOf<Throwable?>(null, IllegalStateException("authored operation failure"))) {
                var phase = initial
                var inputIndex: Int? = if (initial.hasCase) 1 else null
                val cleanup = IOException("authored close failure")
                val thrown = assertFailsWith<IOException> {
                    try {
                        if (primary != null) throw primary
                    } finally {
                        finishGeneratedCValidationSnapshot(primary, close = { throw cleanup }, onFailure = {
                            phase = GeneratedCValidationFailurePhase.SNAPSHOT_FINALIZATION
                            inputIndex = null
                        })
                    }
                }
                assertSame(cleanup, thrown)
                assertEquals(listOfNotNull(primary), cleanup.suppressed.toList())
                assertEquals(GeneratedCValidationFailurePhase.SNAPSHOT_FINALIZATION, phase)
                assertEquals(null, inputIndex)
            }
        }
    }

    @Test
    fun `successful snapshot close preserves the original failing operation and exception`() {
        var phase = GeneratedCValidationFailurePhase.ORIGINAL_OPERATION
        var inputIndex: Int? = 1
        val primary = IllegalStateException("authored operation failure")
        var closes = 0
        var notifications = 0
        val thrown = assertFailsWith<IllegalStateException> {
            try {
                throw primary
            } finally {
                finishGeneratedCValidationSnapshot(primary, close = { closes++ }, onFailure = {
                    notifications++
                    phase = GeneratedCValidationFailurePhase.SNAPSHOT_FINALIZATION
                    inputIndex = null
                })
            }
        }
        assertSame(primary, thrown)
        assertEquals(1, closes)
        assertEquals(0, notifications)
        assertEquals(GeneratedCValidationFailurePhase.ORIGINAL_OPERATION, phase)
        assertEquals(1, inputIndex)
    }

    @Test
    fun `diagnostic observer failure cannot replace the snapshot cleanup throwable`() {
        val primary = IllegalStateException("authored primary")
        val cleanup = IOException("authored cleanup")
        val observation = IllegalArgumentException("authored observer")
        val thrown = assertFailsWith<IOException> {
            finishGeneratedCValidationSnapshot(primary, close = { throw cleanup }, onFailure = { throw observation })
        }
        assertSame(cleanup, thrown)
        assertEquals(listOf(observation, primary), cleanup.suppressed.toList())
    }

    private fun invocation() = RepairValidationInvocation("validation_" + "a".repeat(32), "run_00000001",
        "root_" + "a".repeat(24), "2".repeat(64), "3".repeat(64), "4".repeat(64), "5".repeat(64))

    @Test
    fun `schema two commits the exact typed invocation and remains bounded`() {
        val value = record().copy(invocation = invocation())
        val bytes = value.encode()
        assertEquals(value, parseGeneratedCValidationFailureRecord(bytes))
        assertEquals(2, Json.parseToJsonElement(bytes.toString(Charsets.UTF_8)).jsonObject.getValue("schemaVersion").jsonPrimitive.int)
        assertTrue(bytes.size <= GeneratedCValidationFailureRecord.MAXIMUM_BYTES)
        assertFailsWith<IllegalArgumentException> {
            value.copy(invocation = invocation().copy(sourceRevisionSha256 = "9".repeat(64)))
        }
    }

    @Test
    fun `legacy diagnostic parser retains schema one bytes without inventing an invocation`() {
        val original = record()
        val parsed = parseGeneratedCValidationFailureRecord(original.encode())
        assertEquals(original, parsed)
        assertEquals(null, parsed.invocation)
        assertContentEquals(original.encode(), parsed.encode())
    }

    @Test
    fun `closed diagnostic parser rejects extra fields and quoted numeric values`() {
        val root = Json.parseToJsonElement(record().copy(invocation = invocation()).encode().toString(Charsets.UTF_8)).jsonObject
        val edits = listOf(root + ("PRIVATE-extra" to kotlinx.serialization.json.JsonPrimitive("PRIVATE-value")),
            root + ("inputCount" to kotlinx.serialization.json.JsonPrimitive("3")), root - "invocation")
        for (edit in edits) assertTrue(runCatching {
            parseGeneratedCValidationFailureRecord(decompengine.oracle.core.OracleJson.canonicalBytes(kotlinx.serialization.json.JsonObject(edit)))
        }.isFailure)
    }

    @Test
    fun `same receipt and source with a new invocation produce distinct diagnostic bytes`() {
        val first = record().copy(invocation = invocation())
        val second = first.copy(invocation = invocation().copy(id = "validation_" + "b".repeat(32)))
        assertEquals(first.receiptSha256, second.receiptSha256)
        assertFalse(first.encode().contentEquals(second.encode()))
        assertFalse(sha256(first.encode()) == sha256(second.encode()))
    }

    @Test
    fun `primary marker survives auxiliary failure and accepts one exact successful publication only`() {
        val path = Path.of("/authored/reports/primary.validation.json")
        val primary = GeneratedCValidationFailureEvidence(path, "1".repeat(64), true, RepairValidationFailureKind.RESOURCE_EXHAUSTED)
        val publisher = GeneratedCValidationFailurePublication.start { if (it.isNotEmpty()) throw IOException("authored write") }
        assertFailsWith<IOException> { publisher.publish(record().copy(invocation = invocation()), 1, 4096) }
        assertEquals(null, primary.diagnosticPublication)
        assertEquals("1".repeat(64), primary.receiptSha256)
        val value = RepairValidationDiagnosticPublication(invocation(), "6".repeat(64), path, "1".repeat(64), 1,
            Path.of("/authored/reports/${invocation().id}.validation-failure.json"), "7".repeat(64), 1000,
            RepairValidationFailureKind.RESOURCE_EXHAUSTED, true)
        assertFailsWith<IllegalArgumentException> { primary.retainDiagnostic(value.copy(receiptSha256 = "9".repeat(64))) }
        primary.retainDiagnostic(value)
        assertEquals(value, primary.diagnosticPublication)
        assertFailsWith<IllegalStateException> { primary.retainDiagnostic(value) }
    }

    @Test
    fun `invocation metadata consumes the same retained receipt byte ceiling`() {
        val legacy = record().encode().size
        val value = record().copy(invocation = invocation())
        assertTrue(value.encode().size > legacy)
        assertFailsWith<RepairBudgetExceededException> { value.encodeWithinReceiptBudget(100, 100L + legacy) }
        assertContentEquals(value.encode(), value.encodeWithinReceiptBudget(100, 100L + value.encode().size))
        assertFailsWith<RepairBudgetExceededException> { value.encodeWithinReceiptBudget(100, 100L + value.encode().size, 2) }
        assertContentEquals(value.encode(), value.encodeWithinReceiptBudget(100, 100L + 2 * value.encode().size, 2))
    }

    @Test
    fun `canonical primary and diagnostic copies consume the configured physical retention budget`() {
        val value = record().copy(invocation = invocation())
        val encoded = value.encode()
        val exact = 2L * (100 + encoded.size)
        assertContentEquals(encoded, value.encodeWithinReceiptBudget(100, exact, retainedCopies = 2, receiptCopies = 2))
        assertFailsWith<RepairBudgetExceededException> {
            value.encodeWithinReceiptBudget(100, exact - 1, retainedCopies = 2, receiptCopies = 2)
        }
        assertFailsWith<RepairBudgetExceededException> {
            value.encodeWithinReceiptBudget(Long.MAX_VALUE, Long.MAX_VALUE, retainedCopies = 2, receiptCopies = 2)
        }
        assertFailsWith<IllegalArgumentException> { value.encodeWithinReceiptBudget(100, 4096, receiptCopies = 0) }
        assertFailsWith<IllegalArgumentException> { value.encodeWithinReceiptBudget(100, 4096, receiptCopies = 3) }
    }

    @Test
    fun `the canonical inspection frame fits within sixty four MiB even with a larger physical budget`() {
        val value = record().copy(invocation = invocation())
        val encoded = value.encode()
        val primaryBytes = 64L * 1024 * 1024 - encoded.size
        assertContentEquals(encoded, value.encodeWithinReceiptBudget(primaryBytes, 512L * 1024 * 1024,
            retainedCopies = 2, receiptCopies = 2))
        assertFailsWith<RepairBudgetExceededException> {
            value.encodeWithinReceiptBudget(primaryBytes + 1, 512L * 1024 * 1024, retainedCopies = 2, receiptCopies = 2)
        }
    }

    @Test
    fun `a refused canonical pair leaves the reset supplement unpublished`() {
        val writes = mutableListOf<String>()
        val publisher = GeneratedCValidationFailurePublication.start { writes += it }
        assertFailsWith<RepairBudgetExceededException> {
            publisher.publish(record().copy(invocation = invocation()), 64L * 1024 * 1024,
                512L * 1024 * 1024, retainedCopies = 2, receiptCopies = 2)
        }
        assertEquals(listOf(""), writes)
    }
}
