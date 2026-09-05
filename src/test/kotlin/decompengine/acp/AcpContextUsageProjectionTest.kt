package decompengine.acp

import com.agentclientprotocol.model.Cost
import com.agentclientprotocol.model.SessionUpdate
import decompengine.agent.*
import decompengine.jobs.AgentProgressJournal
import decompengine.project.BoundedAgentExecutionEventRecorder
import decompengine.project.ReconstructionAcpEvidenceArchiveVerifier
import kotlinx.serialization.json.*
import kotlin.io.path.createTempDirectory
import kotlin.test.*

@OptIn(com.agentclientprotocol.annotations.UnstableApi::class)
class AcpContextUsageProjectionTest {
    @Test
    fun `context and cost observations retain exact counts and bounded currency commitments`() {
        val root = createTempDirectory("context-usage-")
        val request = AgentExecutionRequest("fixture", listOf(AgentWorkspaceRoot("project", root)),
            accessPolicy = AgentAccessPolicy(emptyList()))
        val recorder = BoundedAgentExecutionEventRecorder()
        AgentProgressJournal(root, "reconstruction", listOf("private-currency")).use { journal ->
            val task = journal.beginTask("module", request)
            val translator = AcpEventTranslator(request, SequencedEventEmitter {
                recorder.record(it)
                task.event(it)
            }, "fixture")
            translator.onUpdate(SessionUpdate.UsageUpdate(Long.MAX_VALUE, Long.MAX_VALUE, Cost(0.125, "private-currency")))
            translator.onUpdate(SessionUpdate.UsageUpdate(0, 0))
            assertEquals("", translator.summary())
        }
        val observations = AgentProgressJournal.read(root)!!.getValue("events").jsonArray.map { it.jsonObject }.filter {
            it["kind"]?.jsonPrimitive?.content == "context_usage"
        }
        assertEquals(Long.MAX_VALUE.toString(), observations[0].getValue("contextUsedTokens").jsonPrimitive.content)
        assertTrue(observations[0].getValue("contextUsedTokens").jsonPrimitive.isString)
        assertEquals("[redacted]", observations[0].getValue("reportedCostCurrency").jsonPrimitive.content)
        assertFalse("reportedCostAmount" in observations[1])
        val archived = recorder.snapshot().map { event ->
            Json.parseToJsonElement(buildString { event.appendReceiptJson(this) }).jsonObject
        }
        archived.forEach(ReconstructionAcpEvidenceArchiveVerifier::verifyContextUsageEvent)
        assertFalse(archived.toString().contains("private-currency"))
        listOf(
            archived[0] + ("usedTokens" to JsonPrimitive(-1)),
            archived[0] + ("costAmount" to JsonPrimitive("NaN")),
            archived[0] + ("costAmount" to JsonPrimitive("-0.1")),
            archived[0] + ("costCurrency" to JsonNull),
            archived[0] + ("extra" to JsonPrimitive(true)),
        ).forEach { invalid ->
            assertFailsWith<IllegalArgumentException> {
                ReconstructionAcpEvidenceArchiveVerifier.verifyContextUsageEvent(JsonObject(invalid))
            }
        }
    }

    @Test
    fun `invalid peer usage is classified as a protocol failure`() {
        val root = createTempDirectory("context-usage-invalid-")
        val request = AgentExecutionRequest("fixture", listOf(AgentWorkspaceRoot("project", root)),
            accessPolicy = AgentAccessPolicy(emptyList()))
        val translator = AcpEventTranslator(request, SequencedEventEmitter { error("must not emit invalid usage") }, "fixture")
        val failure = assertFailsWith<AgentExecutionException> {
            translator.onUpdate(SessionUpdate.UsageUpdate(-1, 10))
        }
        assertEquals(AgentFailureKind.PROTOCOL, failure.failure.kind)
    }
}
