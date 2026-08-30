package decompengine.mvp

import decompengine.acp.AcpExecutionCleanupDisposition
import decompengine.acp.AcpExecutionEvidenceCompleteness
import decompengine.acp.AcpExecutionLifecyclePhase
import decompengine.acp.AcpInvocationEvidenceSnapshot
import decompengine.agent.AgentExecutionEvent
import decompengine.agent.AgentExecutionOutcome
import decompengine.agent.AgentExecutionReceipt
import decompengine.agent.AgentExecutionRequest
import decompengine.agent.AgentExecutionRequestBinding
import decompengine.agent.AgentExecutionResult
import decompengine.agent.AgentFailure
import decompengine.agent.AgentFailureKind
import decompengine.agent.AgentStopReason
import decompengine.repair.BoundedRepairOutput
import decompengine.repair.CapturedRepairAgentHarness
import decompengine.repair.writeRepairEvidenceAtomically
import java.nio.file.Path
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.pathString
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class MvpPatchReceiptPersistenceTest {
    @Test
    fun `cancel limit and typed failure persist distinct raw and rejected invocation bindings`() {
        val cases = listOf(
            "returned-cancelled" to AgentExecutionOutcome.Returned(AgentExecutionResult(AgentStopReason.CANCELLED)),
            "returned-limit-exhausted" to AgentExecutionOutcome.Returned(
                AgentExecutionResult(AgentStopReason.LIMIT_EXHAUSTED),
            ),
            "failed-protocol" to AgentExecutionOutcome.Failed(
                AgentFailure(AgentFailureKind.PROTOCOL, "peer failure must not be serialized"),
            ),
        )
        cases.forEach { (expectedTerminal, outcome) ->
            val fixture = fixture("mvp-receipt-$expectedTerminal-")
            val harness = OutcomeHarness(outcome)
            assertFailsWith<MvpPatchException>(expectedTerminal) {
                workflow(harness).run(MvpPatchOptions(fixture.input, fixture.output, assumeYes = true))
            }

            assertEquals(1, harness.invocations, expectedTerminal)
            val receiptPath = fixture.output.resolve("evidence/$RECONSTRUCTION_AGENT_EVIDENCE")
            val assessmentPath = fixture.output.resolve("evidence/$RECONSTRUCTION_AGENT_ASSESSMENT")
            assertTrue(receiptPath.exists(), expectedTerminal)
            assertTrue(assessmentPath.exists(), expectedTerminal)
            val receiptText = receiptPath.readText()
            val receipt = Json.parseToJsonElement(receiptText).jsonObject
            val assessment = Json.parseToJsonElement(assessmentPath.readText()).jsonObject
            assertEquals(expectedTerminal,
                assessment.getValue("terminalOutcome").jsonPrimitive.content, expectedTerminal)
            assertEquals("rejected", assessment.getValue("status").jsonPrimitive.content, expectedTerminal)
            assertTrue(assessment.getValue("issues").jsonArray.isNotEmpty(), expectedTerminal)
            assertFalse(receiptText.contains("peer failure must not be serialized"), expectedTerminal)
            assertFalse(fixture.output.resolve("evidence/reconstruction-response.md").exists(), expectedTerminal)
            assertFalse(fixture.output.resolve("patched_binary/patched_binary").exists(), expectedTerminal)
            assertEquals(expectedTerminal,
                receipt.getValue("outcome").jsonObject.let { value ->
                    when (value.getValue("type").jsonPrimitive.content) {
                        "returned" -> "returned-" + value.getValue("result").jsonObject
                            .getValue("stopReason").jsonPrimitive.content
                        else -> "failed-" + value.getValue("failure").jsonObject
                            .getValue("kind").jsonPrimitive.content
                    }
                }, expectedTerminal)
        }
    }

    @Test
    fun `raw receipt persistence failure stops before pending assessment without retry`() {
        val fixture = fixture("mvp-receipt-write-failure-")
        val harness = OutcomeHarness(AgentExecutionOutcome.Returned(AgentExecutionResult(AgentStopReason.CANCELLED)))
        var writes = 0
        val failure = assertFailsWith<MvpPatchException> {
            workflow(harness) { _, _ ->
                writes++
                throw IllegalStateException("simulated raw receipt persistence failure")
            }.run(MvpPatchOptions(fixture.input, fixture.output, assumeYes = true))
        }

        assertTrue(failure.message.orEmpty().contains("persistence failure"))
        assertEquals(1, harness.invocations)
        assertEquals(1, writes)
        assertFalse(fixture.output.resolve("evidence/reconstruction-response.md").exists())
        assertFalse(fixture.output.resolve("patched_binary/patched_binary").exists())
    }

    @Test
    fun `pending assessment persistence failure leaves immutable raw receipt without retry`() {
        val fixture = fixture("mvp-assessment-write-failure-")
        val harness = OutcomeHarness(AgentExecutionOutcome.Returned(AgentExecutionResult(AgentStopReason.CANCELLED)))
        var writes = 0
        assertFailsWith<MvpPatchException> {
            workflow(harness) { path, content ->
                writes++
                if (writes == 2) throw IllegalStateException("simulated pending assessment persistence failure")
                writeRepairEvidenceAtomically(path, content)
            }.run(MvpPatchOptions(fixture.input, fixture.output, assumeYes = true))
        }

        assertEquals(1, harness.invocations)
        assertEquals(2, writes)
        assertTrue(fixture.output.resolve("evidence/$RECONSTRUCTION_AGENT_EVIDENCE").exists())
        assertFalse(fixture.output.resolve("evidence/$RECONSTRUCTION_AGENT_ASSESSMENT").exists())
        assertFalse(fixture.output.resolve("evidence/reconstruction-response.md").exists())
        assertFalse(fixture.output.resolve("patched_binary/patched_binary").exists())
    }

    private fun workflow(
        harness: CapturedRepairAgentHarness,
        persistence: (Path, String) -> Unit = ::writeRepairEvidenceAtomically,
    ): MvpPatchWorkflow = MvpPatchWorkflow(
        harness = harness,
        environment = emptyMap(),
        approve = { true },
        decompiler = BinaryDecompiler { _, _, _, raw -> raw.writeText("int main(void) { return 0; }\n") },
        binaryExecution = executionBoundary(),
        harnessProvenance = "agent-harness-v1:acp:test-receipt-provenance",
        persistAgentEvidence = persistence,
    )

    private fun fixture(prefix: String): Fixture {
        val root = createTempDirectory(prefix)
        val source = root.resolve("original.c")
        val input = root.resolve("original")
        source.writeText("#include <stdio.h>\nint main(void) { puts(\"observable\"); return 0; }\n")
        val process = ProcessBuilder(
            "gcc", "-std=c11", "-Wall", "-Wextra", "-Werror", source.pathString, "-o", input.pathString,
        ).redirectErrorStream(true).start()
        check(process.waitFor() == 0) { process.inputStream.bufferedReader().readText() }
        return Fixture(input, root.resolve("output"))
    }

    private fun executionBoundary() = BinaryExecutionBoundary { executable, directory, environment ->
        val process = ProcessBuilder(executable.toAbsolutePath().toString())
            .directory(directory.toFile())
            .apply { environment().putAll(environment) }
            .start()
        BinaryExecutionResult(
            process.waitFor(),
            process.inputStream.bufferedReader().readText(),
            process.errorStream.bufferedReader().readText(),
            BinaryIsolation("test boundary", networkIsolated = true, credentialsIsolated = true),
        )
    }

    private data class Fixture(val input: Path, val output: Path)

    private class OutcomeHarness(private val outcome: AgentExecutionOutcome) : CapturedRepairAgentHarness {
        var invocations: Int = 0
            private set

        override fun execute(
            request: AgentExecutionRequest,
            onEvent: (AgentExecutionEvent) -> Unit,
        ): AgentExecutionResult = error("captured workflow must not invoke host execution")

        override fun executeCaptured(
            request: AgentExecutionRequest,
            initialFiles: Map<String, ByteArray>,
            output: BoundedRepairOutput,
            onEvent: (AgentExecutionEvent) -> Unit,
        ): AgentExecutionResult = error("receipt-aware workflow must not discard the receipt")

        override fun executeCapturedReceipt(
            request: AgentExecutionRequest,
            initialFiles: Map<String, ByteArray>,
            output: BoundedRepairOutput,
            onEvent: (AgentExecutionEvent) -> Unit,
        ): AgentExecutionReceipt {
            invocations++
            return AgentExecutionReceipt(
                AgentExecutionRequestBinding.capture(request),
                outcome,
                partialEvidence(),
            )
        }

        private fun partialEvidence(): AcpInvocationEvidenceSnapshot = AcpInvocationEvidenceSnapshot(
            factoryProvenance = null,
            phaseReached = AcpExecutionLifecyclePhase.REQUEST_BOUND,
            cleanupDisposition = AcpExecutionCleanupDisposition.NOT_REQUIRED,
            negotiatedAgent = null,
            wirePromptSha256 = null,
            diagnostics = null,
            filesystemAudit = emptyList(),
            terminalAudit = emptyList(),
            permissionAudit = emptyList(),
            sandboxEvidence = null,
            completeness = AcpExecutionEvidenceCompleteness(true, true, true),
            completeExecutionEvidence = null,
        )
    }
}
