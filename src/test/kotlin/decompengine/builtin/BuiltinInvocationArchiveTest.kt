package decompengine.builtin

import decompengine.agent.*
import decompengine.builtin.provider.*
import decompengine.repair.*
import kotlinx.serialization.json.*
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.*

class BuiltinInvocationArchiveTest {
    @TempDir lateinit var directory: Path
    private val base = mapOf("source.c" to "old".toByteArray())
    private fun request(root: AgentWorkspaceRoot, sensitiveContext: String = "private-secret") = AgentExecutionRequest("repair source $sensitiveContext", listOf(root),
        accessPolicy = AgentAccessPolicy(listOf(AgentPathRule(AgentWorkspacePath(root.id, "source.c"), setOf(AgentOperation.READ_FILE, AgentOperation.WRITE_FILE)))))
    private fun response(calls: List<ModelToolCall> = emptyList(), finish: ModelFinishReason = if (calls.isEmpty()) ModelFinishReason.STOP else ModelFinishReason.TOOL_CALLS,
        text: String = "") = ModelResponse(text, calls, finish, ModelUsage(100, 10, false), 1)
    private fun write() = ModelToolCall("write1", "write_text", buildJsonObject { put("root", "project"); put("path", "source.c"); put("content", "candidate") })
    private data class Invocation(val configuration: BuiltinJournalConfiguration, val request: AgentExecutionRequest,
        val receipt: AgentExecutionReceipt, val identity: BuiltinInvocationArchiveIdentity)
    private fun invocation(name: String = "invocation", ending: String = "done", declaredSecrets: List<String> = listOf("private-secret"),
        echoedProviderState: String = ""): Invocation {
        val root = Files.createDirectory(directory.resolve(name))
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
        val source = BuiltinWorkspaceSnapshot.capture(base.mapKeys { AgentWorkspacePath("project", it.key) })
        val configuration = BuiltinJournalConfiguration(root.resolve("journal.jsonl"), BuiltinJournalIdentity("fixture", "scripted-v1", source.sha256,
            "b".repeat(64), "c".repeat(64)))
        var turns = 0
        val provider = ModelProvider { _, _ ->
            if (turns++ == 0) response(listOf(write()), text = echoedProviderState)
            else when (ending) {
                "failed" -> throw ModelProviderException(ModelFailureKind.TRANSPORT)
                "refused" -> response(finish = ModelFinishReason.REFUSED, text = echoedProviderState)
                else -> response(text = echoedProviderState)
            }
        }
        lateinit var request: AgentExecutionRequest
        val execution = CapturedRepairStagingAuthority.executeReceipt(BuiltinCapturedRepairHarness(provider,
            journalConfiguration = configuration, secrets = declaredSecrets), base, setOf("source.c"), RepairResourceBudget(),
            { root -> request(root, declaredSecrets.joinToString(" ")).also { request = it } }) {}
        val identity = BuiltinInvocationArchiveIdentity("repair", "attempt-1", "d".repeat(64), AgentExecutionRequestBinding.capture(request), configuration.identity)
        return Invocation(configuration, request, execution.receipt, identity)
    }
    private fun capture(invocation: Invocation) = BuiltinInvocationArchiveDocument.capture(invocation.identity, invocation.request,
        invocation.receipt, invocation.configuration)
    private fun commitment(invocation: Invocation) = assertIs<BuiltinCapturedExecutionEvidence>(invocation.receipt.providerEvidence).loop.journal!!.commitment
    private fun encode(value: JsonObject) = boundedProviderJson(64 * 1024 * 1024) { it.writeProviderValue(value) }
    private fun root(document: BuiltinInvocationArchiveDocument) = Json.parseToJsonElement(document.bytes.decodeToString()).jsonObject

    @Test fun `portable captured artifact verifies without runtime journal paths and never claims release qualification`() {
        val credential = "credential-sentinel-7d2d"
        val endpoint = "https://provider.invalid/v1?token=endpoint-sentinel-13a1"
        val transientToken = "transient-provider-token-b87c"
        val operatorValue = "operator-config-value-291e"
        val escapedProviderSecret = "escaped\nprovider\"token-61ae"
        val privatePathMarker = "operator-config-path-only-041f"
        val declaredSecrets = listOf("private-secret", credential, endpoint, transientToken, operatorValue, escapedProviderSecret)
        val providerEcho = buildJsonObject {
            declaredSecrets.forEachIndexed { index, secret -> put("state-$index", secret) }
            put("escaped", JsonPrimitive(JsonPrimitive(escapedProviderSecret).toString()))
        }.toString()
        val sentinels = declaredSecrets + privatePathMarker + JsonPrimitive(escapedProviderSecret).toString().drop(1).dropLast(1)
        for ((index, ending) in listOf("done", "refused", "failed").withIndex()) {
            val invocation = invocation("runtime-$privatePathMarker-$index", ending, declaredSecrets, providerEcho)
            assertTrue(invocation.configuration.path.toString().contains(privatePathMarker))
            val document = capture(invocation)
            if (ending == "done") {
                assertTrue(document.verified.candidateEvidenceComplete)
                assertEquals("returned-COMPLETED", document.verified.terminalOutcome)
                assertEquals(invocation.receipt.requestBinding.requestSha256, document.verified.requestSha256)
                assertEquals(1, document.verified.candidateChanges.size)
                val audit = root(document).getValue("receipt").jsonObject.getValue("toolAudit").jsonObject
                assertEquals(1, audit.getValue("filesystem").jsonArray.size)
                assertTrue(audit.getValue("restoration").jsonArray.isEmpty())
            } else {
                assertFalse(document.verified.candidateEvidenceComplete)
                assertFalse(document.verified.releaseComplete)
                assertEquals(ending == "failed", document.verified.indeterminate)
            }
            assertFalse(document.verified.releaseComplete)
            val bytes = document.bytes
            val serialized = bytes.decodeToString()
            sentinels.forEach { assertFalse(serialized.contains(it), "archive leaked a sensitive sentinel") }
            fun assertNoSentinel(value: JsonElement) {
                when (value) {
                    is JsonObject -> value.forEach { (key, child) ->
                        sentinels.forEach { assertFalse(key.contains(it), "archive key leaked a sensitive sentinel") }
                        assertNoSentinel(child)
                    }
                    is JsonArray -> value.forEach(::assertNoSentinel)
                    is JsonPrimitive -> if (value.isString) sentinels.forEach {
                        assertFalse(value.content.contains(it), "archive value leaked a sensitive sentinel")
                    }
                }
            }
            assertNoSentinel(Json.parseToJsonElement(serialized))
            val records = Json.parseToJsonElement(serialized).jsonObject.getValue("records").jsonArray
            records.filter { it.jsonObject.getValue("kind").jsonPrimitive.content == BuiltinJournalKind.MODEL_RESPONSE.name }
                .forEach { record ->
                    val embedded = record.jsonObject.getValue("payload").jsonObject.getValue("text").jsonPrimitive.content
                    assertNoSentinel(Json.parseToJsonElement(embedded))
                }
            Files.delete(invocation.configuration.path)
            val restored = verifyBuiltinInvocationArchive(bytes, invocation.identity, commitment(invocation))
            assertEquals(document.verified.resultChangesSha256, restored.resultChangesSha256)
            assertFalse(restored.releaseComplete)
            val copy = document.bytes; copy[0] = 0
            assertEquals('{'.code.toByte(), document.bytes[0])
            assertEquals(checkpointHash(bytes), document.sha256)
        }
    }

    @Test fun `failed archive binds failure classification to terminal evidence`() {
        val invocation = invocation(ending = "failed")
        val document = capture(invocation)
        val receipt = root(document).getValue("receipt").jsonObject
        assertEquals("PROTOCOL", receipt.getValue("failureKind").jsonPrimitive.content)
        val forged = JsonObject(root(document) + ("receipt" to JsonObject(receipt + ("failureKind" to JsonPrimitive("AUTHENTICATION")))))
        assertFailsWith<BuiltinJournalException> {
            verifyBuiltinInvocationArchive(encode(forged), invocation.identity, commitment(invocation))
        }
    }

    @Test fun `failed and refused turns retain final candidate hashes independently of their result change sets`() {
        for (ending in listOf("failed", "refused")) {
            val invocation = invocation(ending, ending)
            val document = capture(invocation)
            assertFalse(document.verified.candidateEvidenceComplete)
            assertEquals(ending == "failed", document.verified.indeterminate)
            val change = document.verified.candidateChanges.single().jsonObject
            assertEquals(checkpointHash("old".toByteArray()), change.getValue("beforeSha256").jsonPrimitive.content)
            assertEquals(checkpointHash("candidate".toByteArray()), change.getValue("afterSha256").jsonPrimitive.content)
            assertEquals(if (ending == "failed") "failed-PROTOCOL" else "returned-REFUSED", document.verified.terminalOutcome)
            assertFalse(document.verified.releaseComplete)
        }
    }

    @Test fun `task prompt model source and committed journal substitutions are rejected`() {
        val invocation = invocation()
        val document = capture(invocation)
        val identity = invocation.identity
        val identities = listOf(
            BuiltinInvocationArchiveIdentity("repair", "other", identity.promptSha256, identity.binding, identity.journal),
            BuiltinInvocationArchiveIdentity("repair", identity.taskId, "e".repeat(64), identity.binding, identity.journal),
            BuiltinInvocationArchiveIdentity("reconstruction", identity.taskId, identity.promptSha256, identity.binding, identity.journal),
            BuiltinInvocationArchiveIdentity("repair", identity.taskId, identity.promptSha256, identity.binding,
                BuiltinJournalIdentity("fixture", "other-model", identity.journal.sourceSha256, "b".repeat(64), "c".repeat(64))),
        )
        identities.forEach { expected -> assertFailsWith<BuiltinJournalException> {
            verifyBuiltinInvocationArchive(document.bytes, expected, commitment(invocation))
        } }
        assertFailsWith<BuiltinJournalException> { verifyBuiltinInvocationArchive(document.bytes, identity,
            commitment(invocation).copy(headSha256 = "f".repeat(64))) }
    }

    @Test fun `receipt counts changes outcome and cleanup cannot disagree with the terminal journal`() {
        val invocation = invocation()
        val document = capture(invocation)
        val original = root(document)
        val receipt = original.getValue("receipt").jsonObject
        val changes = mapOf<String, JsonElement>("modelCalls" to JsonPrimitive(99), "toolCalls" to JsonPrimitive(99),
            "inputTokens" to JsonPrimitive(99), "candidateChanges" to JsonArray(emptyList()),
            "resultChangesSha256" to JsonPrimitive("e".repeat(64)), "outcome" to JsonPrimitive("returned-NO_CHANGES"),
            "cleanupComplete" to JsonPrimitive(false), "indeterminate" to JsonPrimitive(true), "toolAudit" to JsonNull)
        changes.forEach { (key, value) ->
            val changed = JsonObject(original + ("receipt" to JsonObject(receipt + (key to value))))
            assertFailsWith<BuiltinJournalException> { verifyBuiltinInvocationArchive(encode(changed), invocation.identity, commitment(invocation)) }
        }
        assertFailsWith<BuiltinJournalException> { verifyBuiltinInvocationArchive(encode(JsonObject(original + ("releaseQualified" to JsonPrimitive(true)))),
            invocation.identity, commitment(invocation)) }
    }

    @Test fun `missing reordered duplicate and edited journal records fail exact commitment verification`() {
        val invocation = invocation()
        val document = capture(invocation)
        val original = root(document)
        val records = original.getValue("records").jsonArray
        val variants = listOf(records.dropLast(1), records.reversed(), records + records.last(),
            records.mapIndexed { index, item -> if (index == 1) JsonObject(item.jsonObject + ("kind" to JsonPrimitive("CHECKPOINT"))) else item })
        variants.forEach { variant ->
            assertFailsWith<BuiltinJournalException> { verifyBuiltinInvocationArchive(encode(JsonObject(original + ("records" to JsonArray(variant)))),
                invocation.identity, commitment(invocation)) }
        }
    }

    @Test fun `even rehashed journals reject cross-paired tool results and executable schema extensions`() {
        val invocation = invocation()
        val original = root(capture(invocation))
        for (damage in listOf("result", "schema")) {
            var previous = "0".repeat(64)
            var totalBytes = 0L
            fun sorted(value: JsonElement): JsonElement = when (value) {
                is JsonObject -> JsonObject(value.toSortedMap().mapValues { sorted(it.value) })
                is JsonArray -> JsonArray(value.map(::sorted))
                else -> value
            }
            val records = original.getValue("records").jsonArray.map { item ->
                var record = JsonObject(item.jsonObject - "sha256" + ("previous" to JsonPrimitive(previous)))
                if (damage == "result" && record["kind"] == JsonPrimitive("TOOL_RESULT")) record = JsonObject(record +
                    ("payload" to JsonObject(record.getValue("payload").jsonObject + ("callId" to JsonPrimitive("other-call")))))
                if (damage == "schema" && record["kind"] == JsonPrimitive("MODEL_REQUEST")) {
                    val payload = record.getValue("payload").jsonObject
                    val context = payload.getValue("context").jsonObject
                    val tools = context.getValue("tools").jsonArray.map { tool ->
                        val definition = tool.jsonObject
                        if (definition["name"] == JsonPrimitive("write_text")) JsonObject(definition +
                            ("parameters" to JsonObject(definition.getValue("parameters").jsonObject +
                                ("\$ref" to JsonPrimitive("https://invalid.example/schema"))))) else definition
                    }
                    record = JsonObject(record + ("payload" to JsonObject(payload + ("context" to JsonObject(context + ("tools" to JsonArray(tools)))))))
                }
                previous = checkpointHash(encode(sorted(record).jsonObject))
                val signed = JsonObject(record + ("sha256" to JsonPrimitive(previous)))
                totalBytes += encode(sorted(signed).jsonObject).size + 1
                signed
            }
            val expected = BuiltinJournalCommitment(records.size, totalBytes, previous)
            val changed = JsonObject(original + mapOf("records" to JsonArray(records), "commitment" to buildJsonObject {
                put("records", expected.records); put("bytes", expected.bytes); put("headSha256", expected.headSha256)
            }))
            assertFailsWith<BuiltinJournalException> { verifyBuiltinInvocationArchive(encode(changed), invocation.identity, expected) }
        }
    }

    @Test fun `archive and journal caps plus duplicate or unknown JSON fields fail closed`() {
        val invocation = invocation()
        val document = capture(invocation)
        val limits = listOf(BuiltinInvocationArchiveLimits(maximumBytes = 1024), BuiltinInvocationArchiveLimits(maximumJournalBytes = 1024),
            BuiltinInvocationArchiveLimits(maximumRecordBytes = 512), BuiltinInvocationArchiveLimits(maximumRecords = 2))
        limits.forEach { bound -> assertFailsWith<BuiltinJournalException> {
            verifyBuiltinInvocationArchive(document.bytes, invocation.identity, commitment(invocation), bound)
        } }
        assertFailsWith<BuiltinJournalException> { BuiltinInvocationArchiveDocument.capture(invocation.identity, invocation.request, invocation.receipt,
            invocation.configuration, BuiltinInvocationArchiveLimits(maximumBytes = 1024)) }
        val duplicate = document.bytes.decodeToString().replaceFirst("{", "{\"schemaVersion\":1,")
        assertFailsWith<BuiltinJournalException> { verifyBuiltinInvocationArchive(duplicate.toByteArray(), invocation.identity, commitment(invocation)) }
        assertFailsWith<BuiltinJournalException> { verifyBuiltinInvocationArchive(encode(JsonObject(root(document) + ("extra" to JsonPrimitive(true)))),
            invocation.identity, commitment(invocation)) }
    }
}
