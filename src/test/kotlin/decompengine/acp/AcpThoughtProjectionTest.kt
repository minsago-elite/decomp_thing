package decompengine.acp

import com.agentclientprotocol.model.ContentBlock
import com.agentclientprotocol.model.SessionUpdate
import com.agentclientprotocol.model.MessageId
import decompengine.agent.*
import decompengine.jobs.AgentProgressJournal
import kotlinx.serialization.json.*
import kotlin.io.path.createTempDirectory
import kotlin.test.*

@OptIn(com.agentclientprotocol.annotations.UnstableApi::class)
class AcpThoughtProjectionTest {
    @Test
    fun `prompt completion drains interleaved message IDs once without premature previews`() {
        val root = createTempDirectory("acp-message-drain-")
        val request = AgentExecutionRequest("fixture", listOf(AgentWorkspaceRoot("project", root)),
            accessPolicy = AgentAccessPolicy(emptyList()))
        val events = mutableListOf<AgentMessageEvent>()
        AgentProgressJournal(root, "reconstruction", listOf("private-credential"), maximumQueuedEvents = 1024).use { journal ->
            val task = journal.beginTask("module", request)
            val translator = AcpEventTranslator(request, SequencedEventEmitter {
                events += it as AgentMessageEvent
                task.event(it)
            }, "fixture")
            translator.onUpdate(SessionUpdate.AgentMessageChunk(ContentBlock.Text("private-"), messageId = MessageId("first")))
            translator.onUpdate(SessionUpdate.AgentMessageChunk(ContentBlock.Text("second message"), messageId = MessageId("second")))
            translator.onUpdate(SessionUpdate.AgentMessageChunk(ContentBlock.Text("credential"), messageId = MessageId("first")))
            assertTrue(events.none { it.completed })
            translator.completeMessages()
            translator.completeMessages()
        }
        assertEquals(listOf("first", "second"), events.filter { it.completed }.map { it.messageId })
        val completed = AgentProgressJournal.read(root)!!.getValue("events").jsonArray.map { it.jsonObject }.filter {
            it["completed"]?.jsonPrimitive?.booleanOrNull == true
        }
        assertEquals(listOf("[redacted]", "second message"), completed.map { it.getValue("text").jsonPrimitive.content })
    }

    @Test
    fun `prompt completion retains only bounded message identities`() {
        val root = createTempDirectory("acp-message-bound-")
        val request = AgentExecutionRequest("fixture", listOf(AgentWorkspaceRoot("project", root)),
            accessPolicy = AgentAccessPolicy(emptyList()))
        val events = mutableListOf<AgentMessageEvent>()
        val translator = AcpEventTranslator(request, SequencedEventEmitter { events += it as AgentMessageEvent }, "fixture")
        repeat(100) { index ->
            translator.onUpdate(SessionUpdate.AgentMessageChunk(ContentBlock.Text("fixture"), messageId = MessageId("message-$index")))
        }
        translator.completeMessages()
        assertEquals((0 until 16).map { "message-$it" }, events.filter { it.completed }.map { it.messageId })
        assertEquals(events.indices.map { it.toLong() }, events.map { it.sequence })
    }

    @Test
    fun `thought chunks are distinct redacted messages and never the result summary`() {
        val root = createTempDirectory("acp-thought-projection-")
        val request = AgentExecutionRequest("benign fixture", listOf(AgentWorkspaceRoot("project", root)),
            accessPolicy = AgentAccessPolicy(emptyList()))
        val events = mutableListOf<AgentMessageEvent>()
        AgentProgressJournal(root, "reconstruction", listOf("private-credential"), maximumQueuedEvents = 1024).use { journal ->
            val task = journal.beginTask("module", request)
            val translator = AcpEventTranslator(request, SequencedEventEmitter {
                events += it as AgentMessageEvent
                task.event(it)
            }, "fixture")
            translator.onUpdate(SessionUpdate.AgentThoughtChunk(ContentBlock.Text("private-"), messageId = MessageId("shared")))
            translator.onUpdate(SessionUpdate.AgentMessageChunk(ContentBlock.Text("answer"), messageId = MessageId("shared")))
            translator.onUpdate(SessionUpdate.AgentThoughtChunk(ContentBlock.Text("credential"), messageId = MessageId("shared")))
            translator.completeMessages()
            assertEquals("answer", translator.summary())
        }
        assertEquals(events.indices.map { it.toLong() }, events.map { it.sequence })
        assertEquals(setOf(AgentMessageRole.ASSISTANT, AgentMessageRole.THOUGHT), events.filter { it.completed }.map { it.role }.toSet())
        val snapshot = AgentProgressJournal.read(root)!!
        assertFalse(snapshot.toString().contains("private-"))
        assertFalse(snapshot.toString().contains("credential"))
        val completed = snapshot.getValue("events").jsonArray.map { it.jsonObject }.filter {
            it["completed"]?.jsonPrimitive?.booleanOrNull == true
        }
        assertEquals(mapOf("assistant" to "answer", "thought" to "[redacted]"), completed.associate {
            it.getValue("role").jsonPrimitive.content to it.getValue("text").jsonPrimitive.content
        })
        val recorder = decompengine.project.BoundedAgentExecutionEventRecorder()
        events.forEach(recorder::record)
        val archived = recorder.snapshot().map { event ->
            Json.parseToJsonElement(buildString { event.appendReceiptJson(this) }).jsonObject
        }
        assertEquals(events.map { it.role.name.lowercase() }, archived.map { it.getValue("role").jsonPrimitive.content })
        assertFalse(archived.toString().contains("credential"))
    }
}
