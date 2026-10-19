package decompengine.exploration

import decompengine.validation.BehaviorExecutionOutcomeException
import decompengine.validation.BehaviorExecutionTimeoutException
import decompengine.validation.BehaviorOutputLimitException
import decompengine.validation.SandboxUnavailableException
import kotlinx.serialization.json.*
import java.io.IOException
import kotlin.test.*

/** Synthetic report data only: never instantiate an explorer, sandbox, host or process. */
class ExplorationFailureReportTest {
    private val seed = CandidateInput("seed", CandidateSource.SEED, listOf("\u0001\u001b"), byteArrayOf(0, 65, -1))
    private val generated = CandidateInput("generated", CandidateSource.MUTATION, listOf("next"))
    private val observed = CandidateObservation("seed", "0:00ff:", 0, "00ff", "", false)

    private fun valid() = ExplorationFailureRecord(
        ExplorationSamplePhase.EXPANDED, 0, ExplorationFailureReason.TIMEOUT,
        listOf(seed), listOf(generated), 1, 0, listOf(observed), emptyList(),
    )

    @Test fun `failure capture retains the exact completed sample and original exception without scoring`() {
        lateinit var retained: ExplorationFailureRecord
        val capture = ExplorationFailureCapture(listOf(seed), listOf(generated)) { retained = it }
        capture.completed(ExplorationSamplePhase.BASELINE, observed)
        val failure = BehaviorExecutionTimeoutException("private diagnostic is not report data")
        assertSame(failure, assertFailsWith<BehaviorExecutionTimeoutException> {
            capture.failed(ExplorationSamplePhase.EXPANDED, 0, failure)
        })
        val text = retained.toJson(); val root = Json.parseToJsonElement(text).jsonObject
        assertFalse(text.contains(failure.message!!))
        assertEquals(JsonNull, root.getValue("coverage")); assertEquals(JsonNull, root.getValue("confidence"))
        assertEquals("partial", root.getValue("state").jsonPrimitive.content)
        val details = root.getValue("details").jsonObject
        val input = details.getValue("baselineInputs").jsonArray.single().jsonObject
        assertEquals("\u0001\u001b", input.getValue("args").jsonArray.single().jsonPrimitive.content)
        assertEquals("0041ff", input.getValue("stdinHex").jsonPrimitive.content)
        assertEquals("0:00ff:", details.getValue("baselineObservations").jsonArray.single().jsonObject.getValue("signature").jsonPrimitive.content)
        assertTrue(details.getValue("expandedObservations").jsonArray.isEmpty())
        assertTrue(explorationFailureLimitation(root).contains("a timeout"))
    }

    @Test fun `baseline failure leaves the expanded sample unobserved and tooling unavailable`() {
        lateinit var retained: ExplorationFailureRecord
        val capture = ExplorationFailureCapture(listOf(seed), listOf(generated)) { retained = it }
        val failure = SandboxUnavailableException("sandbox unavailable")
        assertSame(failure, assertFailsWith<SandboxUnavailableException> {
            capture.failed(ExplorationSamplePhase.BASELINE, 0, failure)
        })
        val root = Json.parseToJsonElement(retained.toJson()).jsonObject
        assertEquals(0, root.getValue("samples").jsonObject.getValue("expandedObserved").jsonPrimitive.int)
        assertEquals(0, root.getValue("samples").jsonObject.getValue("baselineObserved").jsonPrimitive.int)
        assertEquals("tooling-unavailable", root.getValue("failure").jsonObject.getValue("kind").jsonPrimitive.content)
        assertTrue(explorationFailureLimitation(root).contains("unavailable sandbox tooling"))
    }

    @Test fun `typed failures remain distinct without interpreting arbitrary messages or reserved exit codes`() {
        for ((failure, reason) in listOf(
            BehaviorExecutionTimeoutException("124") to ExplorationFailureReason.TIMEOUT,
            SandboxUnavailableException("124") to ExplorationFailureReason.SANDBOX_UNAVAILABLE,
            BehaviorOutputLimitException("124") to ExplorationFailureReason.OUTPUT_LIMIT,
            BehaviorExecutionOutcomeException("124") to ExplorationFailureReason.UNVERIFIED_COMPLETION,
            InterruptedException("124") to ExplorationFailureReason.INTERRUPTED,
            IOException("124") to ExplorationFailureReason.IO_FAILURE,
            IllegalStateException("timeout 124") to ExplorationFailureReason.UNCLASSIFIED,
        )) {
            assertEquals(reason, ExplorationFailureReason.from(failure))
            val root = Json.parseToJsonElement(valid().copy(reason = reason).toJson()).jsonObject
            assertTrue(explorationFailureLimitation(root).contains(reason.description))
        }
        assertEquals("0:00ff:", observed.signature)
    }

    @Test fun `retention errors are suppressed once without replacing or retrying the original failure`() {
        for (sameFailure in listOf(false, true)) {
            val original = BehaviorExecutionTimeoutException("deadline")
            val retention = if (sameFailure) original else IOException("storage unavailable")
            var writes = 0
            val capture = ExplorationFailureCapture(listOf(seed), listOf(generated)) { writes++; throw retention }
            assertSame(original, assertFailsWith<BehaviorExecutionTimeoutException> {
                capture.failed(ExplorationSamplePhase.BASELINE, 0, original)
            })
            assertEquals(1, writes)
            assertEquals(if (sameFailure) emptyList() else listOf(retention), original.suppressed.toList())
        }
    }

    @Test fun `oversized detail is explicitly omitted before serialization while sample counts remain exact`() {
        val large = seed.copy(args = listOf("x".repeat(1_048_577)))
        val record = valid().copy(baseline = listOf(large))
        val text = record.toJson(); val root = Json.parseToJsonElement(text).jsonObject
        assertTrue(text.toByteArray().size < 2048)
        assertEquals(JsonNull, root.getValue("details"))
        assertEquals("detail-budget", root.getValue("detailsOmitted").jsonPrimitive.content)
        assertEquals(1, root.getValue("samples").jsonObject.getValue("baselineObserved").jsonPrimitive.int)
        assertTrue(explorationFailureLimitation(root).contains("omitted by its budget"))
        val cases = List(1001) { seed.copy(id = "case_$it") }
        val omitted = valid().copy(phase = ExplorationSamplePhase.BASELINE, candidateIndex = 1000,
            baseline = cases, baselineCompleted = 1000, baselineObserved = emptyList())
        val result = Json.parseToJsonElement(omitted.toJson()).jsonObject
        assertEquals(JsonNull, result.getValue("details"))
        assertEquals(1000, result.getValue("samples").jsonObject.getValue("baselineObserved").jsonPrimitive.int)
        assertTrue(explorationFailureLimitation(result).contains("zero-based position 1000"))
        val manyArguments = valid().copy(phase = ExplorationSamplePhase.BASELINE, candidateIndex = 0,
            baseline = List(400) { seed.copy(args = List(256) { "" }) }, baselineCompleted = 0, baselineObserved = emptyList())
        assertEquals(JsonNull, Json.parseToJsonElement(manyArguments.toJson()).jsonObject.getValue("details"))
    }

    @Test fun `failure reader refuses forged progress numeric coverage signatures and unknown reason pairs`() {
        val root = Json.parseToJsonElement(valid().toJson()).jsonObject
        val failure = root.getValue("failure").jsonObject
        val samples = root.getValue("samples").jsonObject
        val details = root.getValue("details").jsonObject
        val observation = details.getValue("baselineObservations").jsonArray.single().jsonObject
        val invalid = listOf(
            JsonObject(root + ("failure" to JsonObject(failure + ("candidateIndex" to JsonPrimitive(1))))),
            JsonObject(root + ("failure" to JsonObject(failure + ("phase" to JsonPrimitive("baseline"))))),
            JsonObject(root + ("failure" to JsonObject(failure + ("code" to JsonPrimitive("unreported"))))),
            JsonObject(root + ("samples" to JsonObject(samples + ("baselineObserved" to JsonPrimitive(0))))),
            JsonObject(root + ("confidence" to JsonPrimitive(0))),
            JsonObject(root + ("detailsOmitted" to JsonPrimitive("detail-budget"))),
            JsonObject(root + ("details" to JsonObject(details + ("baselineObservations" to JsonArray(listOf(
                JsonObject(observation + ("signature" to JsonPrimitive("1:00ff:"))),
            )))))),
        )
        invalid.forEach { assertFails { explorationFailureLimitation(it) } }
    }
}
