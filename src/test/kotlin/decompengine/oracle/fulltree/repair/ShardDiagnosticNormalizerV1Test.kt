package decompengine.oracle.fulltree.repair

import decompengine.repair.RepairValidationInvocation
import decompengine.repair.RepairValidationObservedArtifact
import java.util.concurrent.CancellationException
import org.junit.jupiter.api.Test
import kotlin.test.*

class ShardDiagnosticNormalizerV1Test {
    private var context = DiagnosticComputationContext()
    private val tool = "a".repeat(64)
    private val receiptSha = "b".repeat(64)
    private val invocation = RepairValidationInvocation(
        "validation_" + "1".padStart(32, '0'), "run_00000001", "root_" + "0".repeat(24),
        "c".repeat(64), "d".repeat(64), "e".repeat(64), "f".repeat(64),
    )

    private fun observation(
        bytes: ByteArray = "error: bad\n".encodeToByteArray(),
        stage: DiagnosticStage = DiagnosticStage.COMPILE,
        toolIdentity: String = tool,
    ) = RecordedDiagnosticObservation(context, stage, toolIdentity, bytes,
        listOf(DiagnosticSpan(DiagnosticStream.STDOUT, 0, bytes.size.toLong())), null, null, FailureClass.OTHER)

    private fun failure(
        stdout: ByteArray = byteArrayOf(1, 2, 3),
        observations: List<RecordedDiagnosticObservation> = emptyList(),
        stage: DiagnosticStage = DiagnosticStage.COMPILE,
        toolIdentity: String = tool,
    ) = RecordedBuildFailure(context, "action-1", "9".repeat(64), stage, toolIdentity, invocation,
        RepairValidationObservedArtifact("reports/repair-revisions/validation-receipts/${invocation.id}_${receiptSha}.json", receiptSha, 1),
        1, stdout, byteArrayOf(), observations, true)

    @Test fun exact_byte_hash_and_committed_v1_key_match_independent_literals() {
        val result = ShardDiagnosticNormalizerV1.normalize(observation())
        assertEquals("3fd40c790f94851b90ec0ea6d7fadaae76a98b7f5e434aa305f4c208ef13d548", result.normalizerSha256)
        assertEquals("8c15acd8f694a1c111d8991ef2dd96691b6bd0f0947a9f1ff4c814b3806049de", result.normalizedKeySha256)
        assertEquals(11L, result.payloadBytes)
        assertEquals("diagnostic-f264b5cb18fa64264c270558051422f5690e0b43c6a1e20fe0cae24b5505ac4d",
            ShardDiagnosticNormalizerV1.stableKey(observation(), result))
        assertFailsWith<DiagnosticInputException> {
            ShardDiagnosticNormalizerV1.stableKey(observation(), result.copy(normalizedKeySha256 = "0".repeat(64)))
        }
    }

    @Test fun any_payload_stage_or_tool_byte_change_changes_the_key() {
        val original = observation()
        val expected = ShardDiagnosticNormalizerV1.stableKey(original, ShardDiagnosticNormalizerV1.normalize(original))
        val variants = listOf(
            observation("error: bad!\n".encodeToByteArray()),
            observation(stage = DiagnosticStage.LINK),
            observation(toolIdentity = "2".repeat(64)),
        )
        variants.forEach { changed ->
            assertNotEquals(expected, ShardDiagnosticNormalizerV1.stableKey(changed, ShardDiagnosticNormalizerV1.normalize(changed)))
        }
    }

    @Test fun invalid_utf8_and_control_bytes_remain_exact_identity_input() {
        val raw = byteArrayOf(0xc3.toByte(), 0x28, 0xff.toByte())
        val recorded = observation(raw)
        val result = ShardDiagnosticNormalizerV1.normalize(recorded)
        assertEquals("7260da181cc952b2a568e214a50e99a75448e8d5c5f01d46da0dae0eae99409c", result.normalizedKeySha256)
        assertContentEquals(raw, recorded.payload)
        assertEquals(3L, result.payloadBytes)
    }

    @Test fun arrays_and_lists_are_snapshotted_and_byte_access_is_a_copy() {
        val source = byteArrayOf(1, 2, 3)
        val spanSource = mutableListOf(DiagnosticSpan(DiagnosticStream.STDOUT, 0, 3))
        val value = RecordedDiagnosticObservation(context, DiagnosticStage.COMPILE, tool, source, spanSource, null, null, FailureClass.OTHER)
        val before = ShardDiagnosticNormalizerV1.normalize(value)
        source[0] = 99
        spanSource.clear()
        value.payload[1] = 99
        assertContentEquals(byteArrayOf(1, 2, 3), value.payload)
        assertEquals(3L, value.spans.single().endExclusive)
        assertEquals(before, ShardDiagnosticNormalizerV1.normalize(value))

        val raw = byteArrayOf(1, 2, 3)
        val build = failure(raw, listOf(observation(raw)))
        raw[1] = 42
        build.stdout[0] = 42
        assertContentEquals(byteArrayOf(1, 2, 3), build.stdout)
    }

    @Test fun payload_and_batch_low_exact_and_one_over_limits() {
        context = DiagnosticComputationContext(ShardDiagnosticLimits(diagnosticPayloadBytes = 3))
        assertFailsWith<DiagnosticInputException> {
            ShardDiagnosticNormalizerV1.normalize(observation("1234".encodeToByteArray()))
        }
        context = DiagnosticComputationContext(ShardDiagnosticLimits(diagnosticPayloadBytes = 4))
        assertEquals(4L, ShardDiagnosticNormalizerV1.normalize(observation("1234".encodeToByteArray())).payloadBytes)
        context = DiagnosticComputationContext()
        assertFailsWith<DiagnosticInputException> { ShardDiagnosticLimits(batchBytes = ShardDiagnosticLimits.HARD_MAX_BATCH_BYTES + 1) }

        val exactly = RecordedCompileLinkBatch(context, listOf(failure(byteArrayOf(1, 2, 3))))
        ShardDiagnosticLimits(batchBytes = 3, actionBytes = 3).admit(exactly)
        ShardDiagnosticLimits(failedActions = 1).admit(exactly)
        assertFailsWith<DiagnosticInputException> { ShardDiagnosticLimits(failedActions = 0).admit(exactly) }
        assertFailsWith<DiagnosticInputException> {
            ShardDiagnosticLimits(batchBytes = 2, actionBytes = 3).admit(exactly)
        }
        assertFailsWith<DiagnosticInputException> {
            ShardDiagnosticLimits(batchBytes = 3, actionBytes = 2).admit(exactly)
        }
        assertFailsWith<DiagnosticInputException> { diagnosticAdd(Long.MAX_VALUE, 1) }

        val twoSpans = failure(byteArrayOf(1), listOf(observation(byteArrayOf(1)), observation(byteArrayOf(1))))
        val twoObservations = RecordedCompileLinkBatch(context, listOf(twoSpans))
        ShardDiagnosticLimits(spansPerAction = 2, spansPerObservation = 1, observations = 2).admit(twoObservations)
        assertFailsWith<DiagnosticInputException> { ShardDiagnosticLimits(observations = 1).admit(twoObservations) }
        assertFailsWith<DiagnosticInputException> { ShardDiagnosticLimits(spansPerObservation = 0).admit(twoObservations) }
        assertFailsWith<DiagnosticInputException> {
            ShardDiagnosticLimits(spansPerAction = 1).admit(RecordedCompileLinkBatch(context, listOf(twoSpans)))
        }
    }

    @Test fun spans_are_range_checked_ordered_and_non_overlapping() {
        val badRange = observation(byteArrayOf(1), stage = DiagnosticStage.COMPILE)
        assertFailsWith<DiagnosticInputException> {
            failure(byteArrayOf(1), listOf(RecordedDiagnosticObservation(context, DiagnosticStage.COMPILE, tool,
                byteArrayOf(1), listOf(DiagnosticSpan(DiagnosticStream.STDOUT, 0, 2)), null, null, FailureClass.OTHER)))
        }
        val overlap = RecordedDiagnosticObservation(context, DiagnosticStage.COMPILE, tool, byteArrayOf(1), listOf(
            DiagnosticSpan(DiagnosticStream.STDOUT, 0, 1), DiagnosticSpan(DiagnosticStream.STDOUT, 0, 1)), null, null, FailureClass.OTHER)
        assertFailsWith<DiagnosticInputException> { failure(byteArrayOf(1), listOf(overlap)) }
        assertEquals(1, badRange.payload.size)
        assertFailsWith<IllegalArgumentException> { DiagnosticSpan(DiagnosticStream.STDERR, -1, 1) }
    }

    @Test fun action_observations_must_match_stage_and_tool() {
        val linked = observation(stage = DiagnosticStage.LINK)
        assertFailsWith<DiagnosticInputException> { failure(byteArrayOf(1), listOf(linked)) }
        val otherTool = observation(toolIdentity = "2".repeat(64))
        assertFailsWith<DiagnosticInputException> { failure(byteArrayOf(1), listOf(otherTool)) }
    }

    @Test fun cancellation_identity_propagates_and_work_budget_exhaustion_is_typed() {
        val cancelled = CancellationException("cancel token")
        val caught = assertFailsWith<CancellationException> {
            context = DiagnosticComputationContext(checkpoint = { throw cancelled })
            ShardDiagnosticNormalizerV1.normalize(observation())
        }
        assertSame(cancelled, caught)
        assertFailsWith<DiagnosticInputException> {
            context = DiagnosticComputationContext(ShardDiagnosticLimits(workUnits = 0))
            ShardDiagnosticNormalizerV1.normalize(observation())
        }.also { assertEquals(DiagnosticInputFailure.WORK_EXHAUSTED, it.failure) }

        var checkpoints = 0
        context = DiagnosticComputationContext(checkpoint = { checkpoints++ })
        val large = observation(ByteArray(1024) { 7 })
        ShardDiagnosticNormalizerV1.normalize(large)
        assertTrue(checkpoints >= 6, "entry/phase/checkpoint cadence should be observable")
    }
}
