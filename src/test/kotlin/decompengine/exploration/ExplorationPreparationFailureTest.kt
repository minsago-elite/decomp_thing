package decompengine.exploration

import kotlinx.serialization.json.*
import java.io.IOException
import kotlin.test.*

/** Callbacks and metadata only; no explorer, sandbox, filesystem or process is instantiated. */
class ExplorationPreparationFailureTest {
    private val seed = CandidateInput("repeat", CandidateSource.SEED, listOf("\u001b"), byteArrayOf(0, -1))
    private val generated = seed.copy(source = CandidateSource.ANGR, args = listOf("generated"))
    private fun valid() = ExplorationPreparationFailureRecord(ExplorationPreparationStage.MUTATIONS,
        ExplorationPreparationReason.FAILED, listOf(seed), listOf(generated), emptyList())

    @Test fun `successful proposal calls each existing stage once in order and preserves positional inputs`() {
        val calls = mutableListOf<String>()
        var retained = 0
        val result = proposeExplorationInputs(listOf(seed),
            angr = { calls += "angr"; listOf(generated) },
            staticHints = { calls += "static"; listOf(seed) },
            mutate = { inputs -> calls += "mutate"; assertEquals(listOf(seed, generated, seed), inputs); listOf(generated) },
            retainFailure = { retained++ })
        assertEquals(listOf("angr", "static", "mutate"), calls)
        assertEquals(listOf(seed, generated, seed, generated), result)
        assertEquals(0, retained)
    }

    @Test fun `failed generation retains only returned groups and rethrows without later callbacks or fake counts`() {
        for (failedStage in ExplorationPreparationStage.entries) {
            val calls = mutableListOf<ExplorationPreparationStage>()
            val original = IllegalStateException("timeout 124 private message")
            lateinit var retained: ExplorationPreparationFailureRecord
            fun run(stage: ExplorationPreparationStage): List<CandidateInput> {
                calls += stage
                if (stage == failedStage) throw original
                return listOf(generated)
            }
            assertSame(original, assertFailsWith<IllegalStateException> {
                proposeExplorationInputs(listOf(seed), { run(ExplorationPreparationStage.ANGR) },
                    { run(ExplorationPreparationStage.STATIC_HINTS) }, { run(ExplorationPreparationStage.MUTATIONS) }, { retained = it })
            })
            assertEquals(ExplorationPreparationStage.entries.take(failedStage.ordinal + 1), calls)
            val bytes = retained.toJson(); val root = Json.parseToJsonElement(bytes).jsonObject
            assertFalse(bytes.contains(original.message!!))
            assertEquals(ExplorationPreparationReason.FAILED, retained.reason)
            val available = root.getValue("availableInputs").jsonObject
            assertEquals(JsonNull, available.getValue("expanded"))
            assertEquals(if (failedStage == ExplorationPreparationStage.ANGR) JsonNull else JsonPrimitive(1), available.getValue("angr"))
            assertEquals(if (failedStage == ExplorationPreparationStage.MUTATIONS) JsonPrimitive(1) else JsonNull, available.getValue("staticHints"))
            assertEquals("not-started", root.getValue("observationState").jsonPrimitive.content)
            assertTrue(explorationPreparationFailureLimitation(root).contains("sample counts are unknown"))
        }
    }

    @Test fun `retention errors remain suppressed on the original generation failure without retries`() {
        for (same in listOf(false, true)) {
            val original = IOException("private")
            val retention = if (same) original else IllegalStateException("retention")
            var calls = 0; var writes = 0
            assertSame(original, assertFailsWith<IOException> {
                proposeExplorationInputs(listOf(seed), { calls++; throw original }, { error("late static") }, { error("late mutation") },
                    { writes++; throw retention })
            })
            assertEquals(1, calls); assertEquals(1, writes)
            assertEquals(if (same) emptyList() else listOf(retention), original.suppressed.toList())
        }
        assertEquals(ExplorationPreparationReason.IO_FAILED, ExplorationPreparationReason.from(IOException("timeout 124")))
        assertEquals(ExplorationPreparationReason.INTERRUPTED, ExplorationPreparationReason.from(InterruptedException("private")))
    }

    @Test fun `oversized preparation details are omitted before allocation while known and unknown counts stay distinct`() {
        val oversized = listOf(
            List(1001) { seed },
            listOf(seed.copy(args = List(257) { "" })),
            listOf(seed.copy(args = listOf("x".repeat(1_048_577)))),
        )
        for (inputs in oversized) {
            val text = valid().copy(seeds = inputs).toJson(); val root = Json.parseToJsonElement(text).jsonObject
            assertTrue(text.toByteArray().size < 2048)
            assertEquals(JsonNull, root.getValue("details")); assertEquals(JsonPrimitive("detail-budget"), root.getValue("detailsOmitted"))
            assertEquals(inputs.size, root.getValue("availableInputs").jsonObject.getValue("seeds").jsonPrimitive.int)
            assertTrue(explorationPreparationFailureLimitation(root).contains("omitted by their budget"))
        }
    }

    @Test fun `preparation reader refuses forged stages availability numeric summaries and input detail`() {
        val root = Json.parseToJsonElement(valid().toJson()).jsonObject
        val available = root.getValue("availableInputs").jsonObject
        val failure = root.getValue("failure").jsonObject
        val details = root.getValue("details").jsonObject
        val seed = details.getValue("seeds").jsonArray.single().jsonObject
        fun changedInput(input: JsonObject) = JsonObject(root + ("details" to JsonObject(details + ("seeds" to JsonArray(listOf(input))))))
        for (invalid in listOf(
            JsonObject(root + ("availableInputs" to JsonObject(available + ("expanded" to JsonPrimitive(0))))),
            JsonObject(root + ("availableInputs" to JsonObject(available + ("angr" to JsonNull)))),
            JsonObject(root + ("failure" to JsonObject(failure + ("stage" to JsonPrimitive("angr-generation"))))),
            JsonObject(root + ("failure" to JsonObject(failure + ("code" to JsonPrimitive("timeout"))))),
            JsonObject(root + ("observationState" to JsonPrimitive("complete"))),
            JsonObject(root + ("coverage" to JsonPrimitive(0))),
            JsonObject(root + ("detailsOmitted" to JsonPrimitive("detail-budget"))),
            changedInput(JsonObject(seed + ("stdinHex" to JsonPrimitive("FF")))),
            changedInput(JsonObject(seed + ("args" to JsonArray(listOf(JsonPrimitive(1)))))),
        )) assertFails { explorationPreparationFailureLimitation(invalid) }
    }
}
