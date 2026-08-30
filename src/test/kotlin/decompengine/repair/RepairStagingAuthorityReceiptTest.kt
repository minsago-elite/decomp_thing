package decompengine.repair

import decompengine.agent.AgentAccessPolicy
import decompengine.agent.AgentExecutionEvent
import decompengine.agent.AgentExecutionOutcome
import decompengine.agent.AgentExecutionProviderEvidence
import decompengine.agent.AgentExecutionReceipt
import decompengine.agent.AgentExecutionRequest
import decompengine.agent.AgentExecutionRequestBinding
import decompengine.agent.AgentExecutionResult
import decompengine.agent.AgentFailure
import decompengine.agent.AgentFailureKind
import decompengine.agent.AgentFileChange
import decompengine.agent.AgentFileChangeKind
import decompengine.agent.AgentHarness
import decompengine.agent.AgentOperation
import decompengine.agent.AgentPathRule
import decompengine.agent.AgentStopReason
import decompengine.agent.AgentWorkspacePath
import decompengine.agent.AgentWorkspaceRoot
import decompengine.project.sha256
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs

class RepairStagingAuthorityReceiptTest {
    @Test
    fun `overlapping captured invocations retain their own request outcome and provider evidence`() {
        val entered = CountDownLatch(2)
        val release = CountDownLatch(1)
        val harness = object : CapturedRepairAgentHarness {
            override fun execute(
                request: AgentExecutionRequest,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult = error("receipt-aware staging must not call execute")

            override fun executeCaptured(
                request: AgentExecutionRequest,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult = error("receipt-aware staging must not call executeCaptured")

            override fun executeCapturedReceipt(
                request: AgentExecutionRequest,
                initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionReceipt {
                entered.countDown()
                check(release.await(5, TimeUnit.SECONDS))
                val tag = request.objective
                val outcome = if (tag == "alpha") {
                    val before = initialFiles.getValue("source")
                    val after = "alpha-result".toByteArray()
                    output.replace("source", after)
                    AgentExecutionOutcome.Returned(
                        AgentExecutionResult(
                            AgentStopReason.COMPLETED,
                            changes = listOf(
                                AgentFileChange(
                                    AgentWorkspacePath("project", "source"),
                                    AgentFileChangeKind.MODIFIED,
                                    sha256(before),
                                    sha256(after),
                                    after.size.toLong(),
                                ),
                            ),
                        ),
                    )
                } else {
                    AgentExecutionOutcome.Failed(AgentFailure(AgentFailureKind.PROTOCOL, "typed failure"))
                }
                return AgentExecutionReceipt(
                    AgentExecutionRequestBinding.capture(request),
                    outcome,
                    TaggedProviderEvidence(tag),
                )
            }
        }
        val executor = Executors.newFixedThreadPool(2)
        try {
            val alpha = executor.submit<Pair<AgentExecutionRequest, RepairStagingExecution>> {
                stage(harness, "alpha")
            }
            val beta = executor.submit<Pair<AgentExecutionRequest, RepairStagingExecution>> {
                stage(harness, "beta")
            }
            check(entered.await(5, TimeUnit.SECONDS))
            release.countDown()

            val (alphaRequest, alphaExecution) = alpha.get(5, TimeUnit.SECONDS)
            val (betaRequest, betaExecution) = beta.get(5, TimeUnit.SECONDS)
            assertEquals(AgentExecutionRequestBinding.capture(alphaRequest), alphaExecution.receipt.requestBinding)
            assertEquals(AgentExecutionRequestBinding.capture(betaRequest), betaExecution.receipt.requestBinding)
            assertEquals("alpha", assertIs<TaggedProviderEvidence>(alphaExecution.receipt.providerEvidence).tag)
            assertEquals("beta", assertIs<TaggedProviderEvidence>(betaExecution.receipt.providerEvidence).tag)
            assertIs<AgentExecutionOutcome.Returned>(alphaExecution.receipt.outcome)
            assertIs<AgentExecutionOutcome.Failed>(betaExecution.receipt.outcome)
            assertContentEquals("alpha-result".toByteArray(), alphaExecution.files.getValue("source"))
            assertContentEquals("before".toByteArray(), betaExecution.files.getValue("source"))
        } finally {
            release.countDown()
            executor.shutdownNow()
        }
    }

    private fun stage(
        harness: AgentHarness,
        objective: String,
    ): Pair<AgentExecutionRequest, RepairStagingExecution> {
        lateinit var request: AgentExecutionRequest
        val execution = CapturedRepairStagingAuthority.executeReceipt(
            harness,
            mapOf("source" to "before".toByteArray()),
            setOf("source"),
            RepairResourceBudget(),
            { root ->
                AgentExecutionRequest(
                    objective,
                    listOf(root),
                    accessPolicy = AgentAccessPolicy(
                        listOf(
                            AgentPathRule(
                                AgentWorkspacePath(root.id, "source"),
                                setOf(AgentOperation.READ_FILE, AgentOperation.WRITE_FILE),
                            ),
                        ),
                    ),
                ).also { request = it }
            },
            {},
        )
        return request to execution
    }

    private class TaggedProviderEvidence(val tag: String) : AgentExecutionProviderEvidence {
        override val providerId: String = "test"
        override val schemaVersion: Int = 1
    }
}
