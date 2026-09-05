package decompengine.builtin

import decompengine.acp.ACP_CAPTURED_REPAIR_WORKSPACE
import decompengine.acp.AcpFilesystemAuditReason
import decompengine.agent.*
import decompengine.builtin.provider.*
import decompengine.repair.*
import kotlinx.serialization.json.*
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.*

class BuiltinCapturedResumeTest {
    @TempDir lateinit var directory: Path
    private fun initial() = mapOf("source.c" to "old".toByteArray(), "other.c" to "unchanged".toByteArray(), "oracle.txt" to "immutable".toByteArray())
    private fun request(root: AgentWorkspaceRoot, files: Map<String, ByteArray>, cancellation: AgentCancellation = AgentCancellation.NONE) =
        AgentExecutionRequest("repair captured source", listOf(root), accessPolicy = AgentAccessPolicy(files.keys.map { path ->
            AgentPathRule(AgentWorkspacePath(root.id, path), if (path == "oracle.txt") setOf(AgentOperation.READ_FILE)
                else setOf(AgentOperation.READ_FILE, AgentOperation.WRITE_FILE))
        }), cancellation = cancellation)
    private fun call(id: String, path: String = "source.c", text: String? = "candidate") = ModelToolCall(id,
        if (text == null) "read_text" else "write_text", buildJsonObject {
            put("root", "project"); put("path", path); text?.let { put("content", it) }
        })
    private fun response(calls: List<ModelToolCall> = emptyList(), finish: ModelFinishReason = if (calls.isEmpty()) ModelFinishReason.STOP else ModelFinishReason.TOOL_CALLS) =
        ModelResponse("", calls, finish, ModelUsage(100, 10, false), 1)
    private fun configurations(name: String, initial: Map<String, ByteArray> = initial(), suspendAfter: Int = 1): Pair<BuiltinJournalConfiguration, BuiltinCheckpointConfiguration> {
        val journal = Files.createDirectory(directory.resolve("$name-journal"))
        val checkpoints = Files.createDirectory(directory.resolve("$name-checkpoints"))
        listOf(journal, checkpoints).forEach { Files.setPosixFilePermissions(it, PosixFilePermissions.fromString("rwx------")) }
        val snapshot = BuiltinWorkspaceSnapshot.capture(initial.mapKeys { AgentWorkspacePath("project", it.key) })
        return BuiltinJournalConfiguration(journal.resolve("journal.jsonl"), BuiltinJournalIdentity("fixture", "scripted-v1",
            snapshot.sha256, "b".repeat(64), "c".repeat(64))) to BuiltinCheckpointConfiguration(checkpoints) { _, calls ->
            if (calls == suspendAfter) BuiltinCheckpointAction.SUSPEND else BuiltinCheckpointAction.CONTINUE
        }
    }
    private fun execute(config: Pair<BuiltinJournalConfiguration, BuiltinCheckpointConfiguration>, provider: ModelProvider,
        initial: Map<String, ByteArray> = initial(), budget: RepairResourceBudget = RepairResourceBudget(),
        resume: BuiltinCapturedResume? = null, cancellation: AgentCancellation = AgentCancellation.NONE,
        writablePaths: Set<String> = initial.keys - "oracle.txt"): RepairStagingExecution =
        CapturedRepairStagingAuthority.executeReceipt(BuiltinCapturedRepairHarness(provider, journalConfiguration = config.first,
            checkpointConfiguration = config.second, resume = resume), initial, writablePaths, budget,
            { root -> request(root, initial, cancellation) }) {}
    private fun evidence(execution: RepairStagingExecution) = assertIs<BuiltinCapturedExecutionEvidence>(execution.receipt.providerEvidence)
    private fun paused(config: Pair<BuiltinJournalConfiguration, BuiltinCheckpointConfiguration>, initial: Map<String, ByteArray> = initial(),
        budget: RepairResourceBudget = RepairResourceBudget(), calls: List<ModelToolCall> = listOf(call("write1"))): RepairStagingExecution =
        execute(config, ModelProvider { _, _ -> response(calls) }, initial, budget).also { assertEquals(BuiltinStop.SUSPENDED, evidence(it).loop.stop) }
    private fun resume(execution: RepairStagingExecution) = BuiltinCapturedResume(assertNotNull(evidence(execution).loop.checkpoint),
        execution.files.mapValues { checkNotNull(it.value) })

    @Test fun `fresh captured stage restores through shared callbacks and preserves the accepted baseline`() {
        val namespaceExists = Files.exists(ACP_CAPTURED_REPAIR_WORKSPACE)
        val config = configurations("fresh")
        val first = paused(config)
        var turn = 0
        val continued = execute(config, ModelProvider { request, _ ->
            if (turn++ == 0) response(listOf(call("read2", text = null)))
            else { assertEquals("candidate", request.messages.last().content); response() }
        }, resume = resume(first))
        assertEquals(BuiltinStop.VALIDATION_REQUIRED, evidence(continued).loop.stop)
        assertEquals(3, evidence(continued).loop.modelCalls); assertEquals(2, evidence(continued).loop.toolCalls)
        assertEquals(checkpointHash("old".toByteArray()), continued.result.changes.single().beforeSha256)
        assertEquals(checkpointHash("candidate".toByteArray()), continued.result.changes.single().afterSha256)
        assertEquals("candidate", continued.files.getValue("source.c")!!.decodeToString())
        assertContentEquals(initial().getValue("oracle.txt"), continued.files.getValue("oracle.txt"))
        assertEquals(listOf("builtin_restore_0"), evidence(continued).restorationAudit.map { it.sessionId })
        assertEquals(listOf("read2"), evidence(continued).filesystemAudit.map { it.sessionId })
        assertTrue(evidence(continued).restorationAudit.all { it.reason == AcpFilesystemAuditReason.COMPLETED })
        assertEquals(namespaceExists, Files.exists(ACP_CAPTURED_REPAIR_WORKSPACE))
    }

    @Test fun `resumed reversion removes prior patches against the original accepted bytes`() {
        val config = configurations("revert")
        val first = paused(config)
        var turn = 0
        val continued = execute(config, ModelProvider { _, _ ->
            if (turn++ == 0) response(listOf(call("revert2", text = "old"))) else response()
        }, resume = resume(first))
        assertEquals(BuiltinStop.VALIDATION_REQUIRED, evidence(continued).loop.stop)
        assertTrue(continued.result.changes.isEmpty()); assertTrue(evidence(continued).candidateChanges.isEmpty())
        initial().forEach { (path, bytes) -> assertContentEquals(bytes, continued.files.getValue(path)) }
    }

    @Test fun `repair budget is bound across resume and prior patches still consume the shared quota`() {
        val config = configurations("budget")
        val budget = RepairResourceBudget(maximumPatchFiles = 1)
        val first = paused(config, budget = budget)
        var calls = 0
        val upgraded = execute(config, ModelProvider { _, _ -> calls++; response() }, budget = budget.copy(maximumPatchFiles = 2), resume = resume(first))
        assertIs<AgentExecutionOutcome.Failed>(upgraded.receipt.outcome); assertEquals(0, calls)
        assertTrue(evidence(upgraded).restorationAudit.isEmpty())
        val continued = execute(config, ModelProvider { _, _ -> calls++; response(listOf(call("write2", "other.c", "second patch"))) },
            budget = budget, resume = resume(first))
        assertEquals(BuiltinStop.TOOL_FAILED, evidence(continued).loop.stop)
        assertEquals(1, calls)
        assertEquals("candidate", continued.files.getValue("source.c")!!.decodeToString())
        assertContentEquals(initial().getValue("other.c"), continued.files.getValue("other.c"))
        assertEquals(1, evidence(continued).candidateChanges.size)
        assertEquals(AcpFilesystemAuditReason.RESOURCE_LIMIT, evidence(continued).filesystemAudit.single().reason)
    }

    @Test fun `invalid candidate inventory content and baseline fail before restoration and leave checkpoint usable`() {
        for (damage in listOf("missing", "extra", "source", "oracle", "baseline")) {
            val config = configurations(damage)
            val first = paused(config)
            val candidate = first.files.mapValues { checkNotNull(it.value) }.toMutableMap()
            var base = initial()
            when (damage) {
                "missing" -> candidate.remove("other.c")
                "extra" -> candidate["extra.c"] = "extra".toByteArray()
                "source" -> candidate["source.c"] = "wrong".toByteArray()
                "oracle" -> candidate["oracle.txt"] = "forged".toByteArray()
                else -> base = initial() + ("source.c" to "wrong base".toByteArray())
            }
            var calls = 0
            val invalid = execute(config, ModelProvider { _, _ -> calls++; response() }, initial = base,
                resume = BuiltinCapturedResume(evidence(first).loop.checkpoint!!, candidate))
            assertIs<AgentExecutionOutcome.Failed>(invalid.receipt.outcome); assertEquals(0, calls)
            assertTrue(evidence(invalid).restorationAudit.isEmpty()); assertTrue(evidence(invalid).candidateChanges.isEmpty())
            val corrected = execute(config, ModelProvider { _, _ -> calls++; response() }, resume = resume(first))
            assertEquals(BuiltinStop.VALIDATION_REQUIRED, evidence(corrected).loop.stop); assertEquals(1, calls)
        }
    }

    @Test fun `restoration shrinks before growing so a valid stage never exceeds its aggregate quota`() {
        val base = mapOf("a.c" to "a".toByteArray(), "z.c" to "z".repeat(100).toByteArray())
        val config = configurations("order", base, suspendAfter = 2)
        val budget = RepairResourceBudget(maximumStagingBytes = 101)
        val first = paused(config, base, budget, listOf(call("shrink1", "z.c", "z"), call("grow2", "a.c", "a".repeat(100))))
        val continued = execute(config, ModelProvider { _, _ -> response() }, base, budget, resume(first))
        assertEquals(BuiltinStop.VALIDATION_REQUIRED, evidence(continued).loop.stop)
        assertEquals(listOf("z.c", "a.c"), evidence(continued).restorationAudit.map { it.policyPath!!.relativePath })
        assertEquals(2, continued.result.changes.size)
        assertEquals(101, continued.files.values.sumOf { it!!.size })
    }

    @Test fun `resume input snapshots detach caller buffers and reject noncanonical names`() {
        val config = configurations("detached")
        val first = paused(config)
        val mutable = first.files.mapValues { checkNotNull(it.value) }.toMutableMap()
        val reference = evidence(first).loop.checkpoint!!
        val supplied = BuiltinCapturedResume(reference, mutable)
        mutable.getValue("source.c")[0] = 0; mutable.clear()
        val continued = execute(config, ModelProvider { _, _ -> response() }, resume = supplied)
        assertEquals("candidate", continued.files.getValue("source.c")!!.decodeToString())
        for (path in listOf("../outside", "a/../source.c", "a\\b", "/absolute")) {
            assertFailsWith<IllegalArgumentException> { BuiltinCapturedResume(reference, mapOf(path to byteArrayOf(1))) }
        }
        assertFalse(supplied.toString().contains("candidate"))
    }

    @Test fun `refusal provider failure and cancellation after continuation retain all candidate hashes`() {
        for (stop in listOf("refusal", "provider", "cancel")) {
            val config = configurations(stop)
            val first = paused(config)
            val cancellation = AgentCancellationSource()
            var turn = 0
            val continued = execute(config, ModelProvider { _, _ ->
                if (turn++ == 0) response(listOf(call("write2", text = "later candidate")))
                else when (stop) {
                    "refusal" -> response(finish = ModelFinishReason.REFUSED)
                    "provider" -> throw ModelProviderException(ModelFailureKind.TRANSPORT)
                    else -> { cancellation.cancel(); response() }
                }
            }, resume = resume(first), cancellation = cancellation.cancellation)
            assertEquals(when (stop) { "refusal" -> BuiltinStop.REFUSED; "provider" -> BuiltinStop.PROVIDER_FAILED; else -> BuiltinStop.CANCELLED },
                evidence(continued).loop.stop)
            assertEquals("later candidate", continued.files.getValue("source.c")!!.decodeToString())
            val change = evidence(continued).candidateChanges.single()
            assertEquals(checkpointHash("old".toByteArray()), change.beforeSha256)
            assertEquals(checkpointHash("later candidate".toByteArray()), change.afterSha256)
            assertEquals(2, evidence(continued).loop.toolCalls)
        }
    }

    @Test fun `effective sink write authority cannot expand behind unchanged request rules`() {
        val config = configurations("sink-authority")
        val first = execute(config, ModelProvider { _, _ -> response(listOf(call("write1"))) }, writablePaths = setOf("source.c"))
        assertEquals(BuiltinStop.SUSPENDED, evidence(first).loop.stop)
        var calls = 0
        val expanded = execute(config, ModelProvider { _, _ -> calls++; response() }, resume = resume(first))
        assertIs<AgentExecutionOutcome.Failed>(expanded.receipt.outcome); assertEquals(0, calls)
        assertTrue(evidence(expanded).restorationAudit.isEmpty())
        val corrected = execute(config, ModelProvider { _, _ -> calls++; response() }, resume = resume(first), writablePaths = setOf("source.c"))
        assertEquals(BuiltinStop.VALIDATION_REQUIRED, evidence(corrected).loop.stop); assertEquals(1, calls)
    }
}
