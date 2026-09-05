package decompengine.builtin

import decompengine.agent.*
import decompengine.builtin.provider.*
import kotlinx.serialization.json.*
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption.APPEND
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.*

class BuiltinJournalTest {
    @TempDir lateinit var directory: Path
    private val identity = BuiltinJournalIdentity("fixture", "scripted-v1", "a".repeat(64), "b".repeat(64), "c".repeat(64))
    private fun request(root: Path = Path.of("/fixture/project")) = AgentExecutionRequest("inspect source",
        listOf(AgentWorkspaceRoot("project", root)), emptyList(), AgentAccessPolicy(emptyList()))
    private fun configuration(name: String = "journal.jsonl", bytes: Long = 64L * 1024 * 1024,
        recordBytes: Int = 8 * 1024 * 1024, records: Int = 10_000): BuiltinJournalConfiguration {
        Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("rwx------"))
        return BuiltinJournalConfiguration(directory.resolve(name), identity, bytes, recordBytes, records)
    }
    private fun inspect(configuration: BuiltinJournalConfiguration, commitment: BuiltinJournalCommitment,
        request: AgentExecutionRequest = request()) = BuiltinJournal.inspect(configuration, AgentExecutionRequestBinding.capture(request), commitment)

    @Test fun `durable canonical chain binds trusted identities and replays deterministically`() {
        fun write(name: String): Pair<BuiltinJournalConfiguration, BuiltinJournalCommitment> {
            val configuration = configuration(name)
            val journal = BuiltinJournal.open(configuration, request(), emptyList())
            journal.use {
                it.append(BuiltinJournalKind.CHECKPOINT, if (name == "one") buildJsonObject { put("state", "fixture"); put("remainingTurns", 2) }
                    else buildJsonObject { put("remainingTurns", 2); put("state", "fixture") })
            }
            return configuration to journal.evidence.commitment
        }
        val (first, commitment) = write("one")
        val (second, other) = write("two")
        assertEquals(commitment, other)
        assertContentEquals(Files.readAllBytes(first.path), Files.readAllBytes(second.path))
        val restored = inspect(first, commitment)
        assertTrue(restored.endsAtCheckpoint)
        assertFalse(restored.complete)
        assertFalse(restored.indeterminate)
        assertEquals("a".repeat(64), restored.records.first().getValue("payload").jsonObject.getValue("sourceSha256").jsonPrimitive.content)
        assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(first.path))
    }

    @Test fun `redaction covers nested keys escaping overlapping secrets and bounded full payloads`() {
        val configuration = configuration()
        val journal = BuiltinJournal.open(configuration, request(), listOf("abc", "bcd", "a\"b"))
        journal.use {
            it.append(BuiltinJournalKind.CHECKPOINT, buildJsonObject {
                putJsonObject("abc") { put("text", "abcd and a\"b"); put("encoded", JsonPrimitive("a\"b").toString()) }
            })
        }
        val payload = inspect(configuration, journal.evidence.commitment).records.last().getValue("payload").jsonObject
        val child = payload.getValue("[REDACTED]").jsonObject
        assertEquals("[REDACTED] and [REDACTED]", child.getValue("text").jsonPrimitive.content)
        assertEquals("\"[REDACTED]\"", child.getValue("encoded").jsonPrimitive.content)
        assertFalse(Files.readString(configuration.path).contains("abc"))
    }

    @Test fun `tampered truncated appended and substituted request journals are rejected`() {
        val configuration = configuration()
        val journal = BuiltinJournal.open(configuration, request(), emptyList())
        journal.use { it.append(BuiltinJournalKind.TERMINAL) }
        val expected = journal.evidence.commitment
        val original = Files.readAllBytes(configuration.path)
        assertFailsWith<BuiltinJournalException> { inspect(configuration, expected, request(Path.of("/different/project"))) }
        val otherIdentity = BuiltinJournalConfiguration(configuration.path,
            BuiltinJournalIdentity("fixture", "different", "a".repeat(64), "b".repeat(64), "c".repeat(64)))
        assertFailsWith<BuiltinJournalException> { inspect(otherIdentity, expected) }
        val firstLine = original.indexOf(10).let { original.copyOf(it + 1) }
        listOf(original.copyOf(original.size - 1), original + byteArrayOf(10), firstLine,
            original.copyOf().also { it[10] = (it[10].toInt() xor 1).toByte() }).forEach { invalid ->
            Files.write(configuration.path, invalid)
            assertFailsWith<BuiltinJournalException> { inspect(configuration, expected) }
        }
        Files.write(configuration.path, original)
        assertTrue(inspect(configuration, expected).complete)
    }

    @Test fun `active writers existing files links unsafe permissions and workspace containment are rejected`() {
        val configuration = configuration()
        val journal = BuiltinJournal.open(configuration, request(), emptyList())
        journal.use {
            assertFailsWith<BuiltinJournalException> { inspect(configuration, it.evidence.commitment) }
            assertFailsWith<BuiltinJournalException> { BuiltinJournal.open(configuration, request(), emptyList()) }
        }
        val linked = configuration("linked")
        Files.createSymbolicLink(linked.path, configuration.path)
        assertFailsWith<BuiltinJournalException> { BuiltinJournal.open(linked, request(), emptyList()) }
        assertFailsWith<BuiltinJournalException> { inspect(linked, journal.evidence.commitment) }
        Files.createLink(directory.resolve("hardlink"), configuration.path)
        assertFailsWith<BuiltinJournalException> { inspect(configuration, journal.evidence.commitment) }
        Files.delete(directory.resolve("hardlink"))
        assertFailsWith<BuiltinJournalException> { BuiltinJournal.open(configuration("contained"), request(directory), emptyList()) }
        val unsafe = configuration("unsafe")
        Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("rwxr-xr-x"))
        assertFailsWith<BuiltinJournalException> { BuiltinJournal.open(unsafe, request(), emptyList()) }
    }

    @Test fun `record byte total byte and event ceilings fail without extending the committed prefix`() {
        val variants = listOf(configuration("record", 8192, 1024), configuration("total", 1100, 1100),
            configuration("count", records = 2))
        variants.forEachIndexed { index, configuration ->
            val journal = BuiltinJournal.open(configuration, request(), emptyList())
            if (index == 2) journal.append(BuiltinJournalKind.STATE)
            val prefix = journal.evidence.commitment
            journal.use {
                assertFailsWith<BuiltinJournalException> { it.append(BuiltinJournalKind.CHECKPOINT,
                    buildJsonObject { put("content", "x".repeat(if (index == 0) 2000 else 700)) }) }
            }
            assertEquals(prefix.bytes, Files.size(configuration.path))
            assertFalse(journal.evidence.complete)
            inspect(configuration, prefix)
        }
    }

    @Test fun `unresolved model tool and validation operations survive terminal failure and forbid checkpoint`() {
        listOf(BuiltinJournalKind.MODEL_REQUEST, BuiltinJournalKind.TOOL_REQUEST, BuiltinJournalKind.VALIDATION_REQUEST).forEachIndexed { index, kind ->
            val configuration = configuration("pending-$index")
            val journal = BuiltinJournal.open(configuration, request(), emptyList())
            journal.use {
                it.append(BuiltinJournalKind.CHECKPOINT)
                it.append(kind)
                it.append(BuiltinJournalKind.TERMINAL, buildJsonObject { put("stop", "TOOL_FAILED") })
            }
            val restored = inspect(configuration, journal.evidence.commitment)
            assertTrue(restored.complete)
            assertTrue(restored.indeterminate)
            assertFalse(restored.endsAtCheckpoint)
        }
        val journal = BuiltinJournal.open(configuration("no-checkpoint"), request(), emptyList())
        journal.use {
            it.append(BuiltinJournalKind.TOOL_REQUEST)
            assertFailsWith<BuiltinJournalException> { it.append(BuiltinJournalKind.CHECKPOINT) }
        }
    }

    @Test fun `loop records full model policy tool validation and terminal evidence with cross-delta redaction`() {
        val configuration = configuration()
        val session = Session()
        var turn = 0
        val provider = ModelProvider { _, emit ->
            if (turn++ == 0) {
                emit(ModelEvent.TextDelta("se")); emit(ModelEvent.TextDelta("cret"))
                ModelResponse("secret", listOf(ModelToolCall("call1", "edit", buildJsonObject { put("text", "secret") })),
                    ModelFinishReason.TOOL_CALLS, ModelUsage(100, 10, false), 1)
            } else ModelResponse("done", emptyList(), ModelFinishReason.STOP, ModelUsage(100, 10, false), 1)
        }
        val receipt = BuiltinAgentHarness(provider, { _, _ -> session }, secrets = listOf("secret"), journalConfiguration = configuration)
            .executeReceipt(request()) {}
        val evidence = assertIs<BuiltinLoopEvidence>(receipt.providerEvidence).journal!!
        assertTrue(evidence.complete); assertFalse(evidence.indeterminate)
        assertTrue(session.closed); assertEquals(1, session.executions)
        val restored = inspect(configuration, evidence.commitment)
        val kinds = restored.records.map { it.getValue("kind").jsonPrimitive.content }
        assertEquals(2, kinds.count { it == "MODEL_REQUEST" })
        assertEquals(2, kinds.count { it == "MODEL_RESPONSE" })
        listOf("CHECKPOINT", "POLICY", "TOOL_REQUEST", "TOOL_RESULT", "VALIDATION_REQUEST", "VALIDATION_RESULT", "TERMINAL").forEach {
            assertEquals(1, kinds.count { kind -> kind == it })
        }
        val response = restored.records.first { it["kind"] == JsonPrimitive("MODEL_RESPONSE") }.getValue("payload").jsonObject
        assertEquals("[REDACTED]", response.getValue("text").jsonPrimitive.content)
        assertFalse(Files.readString(configuration.path).contains("secret"))
    }

    @Test fun `interrupted tool remains indeterminate and inspection never reexecutes it`() {
        val configuration = configuration()
        val session = Session(fail = true)
        val provider = ModelProvider { _, _ -> ModelResponse("", listOf(ModelToolCall("call1", "edit", buildJsonObject { put("text", "candidate") })),
            ModelFinishReason.TOOL_CALLS, ModelUsage(100, 10, true), 1) }
        val receipt = BuiltinAgentHarness(provider, { _, _ -> session }, journalConfiguration = configuration).executeReceipt(request()) {}
        assertIs<AgentExecutionOutcome.Failed>(receipt.outcome)
        val evidence = assertIs<BuiltinLoopEvidence>(receipt.providerEvidence).journal!!
        assertTrue(evidence.indeterminate)
        assertTrue(inspect(configuration, evidence.commitment).indeterminate)
        assertEquals(1, session.executions)
        assertFalse(Files.readString(configuration.path).contains("private exception"))
    }

    @Test fun `journal capacity prevents provider invocation and failure after an effect cannot become success`() {
        val small = configuration("small", records = 2)
        var calls = 0
        val rejected = BuiltinAgentHarness(ModelProvider { _, _ -> calls++; error("Not reached") }, { _, _ -> Session() },
            journalConfiguration = small).executeReceipt(request()) {}
        assertEquals(0, calls)
        assertIs<AgentExecutionOutcome.Failed>(rejected.outcome)
        assertFalse(assertIs<BuiltinLoopEvidence>(rejected.providerEvidence).journal!!.complete)
        val configuration = configuration("after-effect")
        val session = Session(afterExecute = { Files.writeString(configuration.path, "damage", APPEND) })
        val provider = ModelProvider { _, _ -> ModelResponse("", listOf(ModelToolCall("call1", "edit", buildJsonObject { put("text", "candidate") })),
            ModelFinishReason.TOOL_CALLS, ModelUsage(100, 10, true), 1) }
        val damaged = BuiltinAgentHarness(provider, { _, _ -> session }, journalConfiguration = configuration).executeReceipt(request()) {}
        assertEquals(1, session.executions)
        assertIs<AgentExecutionOutcome.Failed>(damaged.outcome)
        val evidence = assertIs<BuiltinLoopEvidence>(damaged.providerEvidence).journal!!
        assertFalse(evidence.complete); assertTrue(evidence.indeterminate)
        assertFailsWith<BuiltinJournalException> { inspect(configuration, evidence.commitment) }
    }

    @Test fun `redacted identity and colliding redacted keys fail closed`() {
        assertFailsWith<BuiltinJournalException> { BuiltinJournal.open(configuration("identity"), request(), listOf("scripted-v1")) }
        val journal = BuiltinJournal.open(configuration("keys"), request(), listOf("private-one", "private-two"))
        journal.use {
            assertFailsWith<BuiltinJournalException> { it.append(BuiltinJournalKind.CHECKPOINT,
                buildJsonObject { put("private-one", 1); put("private-two", 2) }) }
        }
    }

    @Test fun `partial provider streams and interrupted completion validation remain unresolved`() {
        val streaming = configuration("streaming")
        val partial = BuiltinAgentHarness(ModelProvider { _, emit ->
            emit(ModelEvent.TextDelta("private-"))
            throw ModelProviderException(ModelFailureKind.TRANSPORT)
        }, { _, _ -> Session() }, secrets = listOf("private-secret"), journalConfiguration = streaming).executeReceipt(request()) {}
        val partialEvidence = assertIs<BuiltinLoopEvidence>(partial.providerEvidence).journal!!
        assertTrue(inspect(streaming, partialEvidence.commitment).indeterminate)
        assertFalse(Files.readString(streaming.path).contains("private-"))
        val validating = configuration("validation")
        val session = object : BuiltinToolSession {
            override val definitions = emptyList<ModelToolDefinition>()
            override fun authorize(call: ModelToolCall, control: BuiltinExecutionControl) = false
            override fun execute(call: ModelToolCall, control: BuiltinExecutionControl): BuiltinToolResult = error("Unexpected")
            override fun changes(control: BuiltinExecutionControl) = emptyList<AgentFileChange>()
            override fun validateCompletion(control: BuiltinExecutionControl): BuiltinCompletion = error("Interrupted validation")
            override fun close() = Unit
        }
        val failed = BuiltinAgentHarness(ModelProvider { _, _ -> ModelResponse("done", emptyList(), ModelFinishReason.STOP,
            ModelUsage(100, 10, false), 1) }, { _, _ -> session }, journalConfiguration = validating).executeReceipt(request()) {}
        assertIs<AgentExecutionOutcome.Failed>(failed.outcome)
        assertTrue(inspect(validating, assertIs<BuiltinLoopEvidence>(failed.providerEvidence).journal!!.commitment).indeterminate)
    }

    private class Session(val fail: Boolean = false, val afterExecute: () -> Unit = {}) : BuiltinToolSession {
        var executions = 0
        var closed = false
        override val definitions = listOf(ModelToolDefinition("edit", "Change fixture", buildJsonObject {
            put("type", "object"); put("additionalProperties", false)
            putJsonObject("properties") { putJsonObject("text") { put("type", "string") } }
            putJsonArray("required") { add("text") }
        }))
        override fun authorize(call: ModelToolCall, control: BuiltinExecutionControl) = true
        override fun execute(call: ModelToolCall, control: BuiltinExecutionControl): BuiltinToolResult {
            executions++; afterExecute()
            if (fail) error("private exception")
            return BuiltinToolResult("secret result")
        }
        override fun changes(control: BuiltinExecutionControl) = emptyList<AgentFileChange>()
        override fun close() { closed = true }
    }
}
