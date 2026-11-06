package decompengine.acp

import com.agentclientprotocol.protocol.AcpExpectedError
import decompengine.agent.AgentAccessPolicy
import decompengine.agent.AgentExecutionException
import decompengine.agent.AgentExecutionRequest
import decompengine.agent.AgentFailureKind
import decompengine.agent.AgentOperation
import decompengine.agent.AgentMutationAuthority
import decompengine.agent.AgentMutationContentKind
import decompengine.agent.AgentMutationGrant
import decompengine.agent.AgentPathRule
import decompengine.agent.AgentWorkspacePath
import decompengine.agent.AgentWorkspaceRoot
import decompengine.repair.BoundedRepairOutput
import decompengine.repair.RepairResourceBudget
import java.nio.file.Files
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class AcpCapturedRepairFilesystemTest {
    @Test
    fun `captured text inputs fail preflight before a process can start`() {
        val invalidUtf8 = mapOf("src/module.c" to byteArrayOf(0xc3.toByte(), 0x28))
        val invalidOutput = BoundedRepairOutput(invalidUtf8, invalidUtf8.keys, RepairResourceBudget())
        val invalid = AcpCapturedRepairFilesystem(invalidUtf8, invalidOutput)

        val invalidFailure = assertFailsWith<AgentExecutionException> {
            invalid.preflight(request(), AcpFilesystemLimits())
        }
        assertEquals(AgentFailureKind.WORKSPACE_VIOLATION, invalidFailure.failure.kind)

        val oversized = mapOf("src/module.c" to "12345".toByteArray())
        val oversizedOutput = BoundedRepairOutput(oversized, oversized.keys, RepairResourceBudget())
        val oversizedFilesystem = AcpCapturedRepairFilesystem(oversized, oversizedOutput)
        val oversizedFailure = assertFailsWith<AgentExecutionException> {
            oversizedFilesystem.preflight(
                request(),
                AcpFilesystemLimits(maximumReadBytes = 4),
            )
        }
        assertEquals(AgentFailureKind.RESOURCE_EXHAUSTED, oversizedFailure.failure.kind)
    }

    @Test
    fun `captured callbacks read current bytes and publish only the final bounded replacement`() {
        val initial = mapOf("src/module.c" to "old source\n".toByteArray())
        val output = BoundedRepairOutput(initial, initial.keys, RepairResourceBudget())
        val audit = AcpFilesystemAuditRecorder()
        val captured = AcpCapturedRepairFilesystem(initial, output)
        val existedBefore = Files.exists(ACP_CAPTURED_REPAIR_WORKSPACE)
        val session = captured.open(request(), AcpFilesystemLimits(), audit)

        runBlocking {
            assertEquals(
                "old source\n",
                session.readTextFile(
                    "captured-session",
                    "$ACP_CAPTURED_REPAIR_WORKSPACE/src/module.c",
                    null,
                    null,
                ).content,
            )
            session.writeTextFile(
                "captured-session",
                "$ACP_CAPTURED_REPAIR_WORKSPACE/src/module.c",
                "intermediate source\n",
            )
            session.writeTextFile(
                "captured-session",
                "$ACP_CAPTURED_REPAIR_WORKSPACE/src/module.c",
                "final source\n",
            )
            assertEquals(
                "final source\n",
                session.readTextFile(
                    "captured-session",
                    "$ACP_CAPTURED_REPAIR_WORKSPACE/src/module.c",
                    null,
                    null,
                ).content,
            )
        }
        session.close()

        val change = captured.changes().single()
        assertEquals("src/module.c", change.path.relativePath)
        assertContentEquals("final source\n".toByteArray(), output.finish().getValue("src/module.c"))
        assertEquals(existedBefore, Files.exists(ACP_CAPTURED_REPAIR_WORKSPACE))
        assertEquals(
            listOf(
                AcpFilesystemAuditReason.COMPLETED,
                AcpFilesystemAuditReason.COMPLETED,
                AcpFilesystemAuditReason.COMPLETED,
                AcpFilesystemAuditReason.COMPLETED,
            ),
            audit.snapshot().map { it.reason },
        )
    }

    @Test
    fun `repair quotas reject a callback before it replaces the captured state`() {
        val initial = mapOf("src/module.c" to "old\n".toByteArray())
        val output = BoundedRepairOutput(
            initial,
            initial.keys,
            RepairResourceBudget(maximumStagingBytes = 5, maximumPatchBytes = 5),
        )
        val audit = AcpFilesystemAuditRecorder()
        val captured = AcpCapturedRepairFilesystem(initial, output)
        val session = captured.open(request(), AcpFilesystemLimits(), audit)

        runBlocking {
            session.writeTextFile(
                "captured-session",
                "$ACP_CAPTURED_REPAIR_WORKSPACE/src/module.c",
                "12345",
            )
        }
        assertFailsWith<AcpExpectedError> {
            runBlocking {
                session.writeTextFile(
                    "captured-session",
                    "$ACP_CAPTURED_REPAIR_WORKSPACE/src/module.c",
                    "123456",
                )
            }
        }
        session.close()

        assertContentEquals("12345".toByteArray(), output.finish().getValue("src/module.c"))
        assertEquals(5L, captured.changes().single().sizeBytes)
        assertEquals(AcpFilesystemAuditReason.RESOURCE_LIMIT, audit.snapshot().last().reason)
        assertEquals(AcpFilesystemAuditOutcome.DENIED, audit.snapshot().last().outcome)
    }

    @Test
    fun `captured sink enforces request-bound role content and size authority`() {
        val path = AgentWorkspacePath("project", "src/module.c")
        val owner = "test-owner"
        val digest = "a".repeat(64)
        val authority = AgentMutationAuthority(
            "declared-role-test-v1", owner, digest,
            listOf(AgentMutationGrant(
                path, setOf(AgentOperation.WRITE_FILE), owner, digest, "source",
                setOf("editable"), AgentMutationContentKind.UTF8_TEXT, 4,
            )),
        )
        val access = AgentAccessPolicy(
            listOf(AgentPathRule(path, setOf(AgentOperation.READ_FILE, AgentOperation.WRITE_FILE))),
            mutationAuthority = authority,
        )
        val initial = mapOf("src/module.c" to "old".toByteArray())
        val output = BoundedRepairOutput(initial, initial.keys, RepairResourceBudget(), access)
        assertFailsWith<IllegalArgumentException> { output.replace("src/module.c", byteArrayOf(0xc3.toByte(), 0x28)) }
        assertFailsWith<IllegalArgumentException> { output.replace("src/module.c", "12345".toByteArray()) }
        assertEquals(emptyMap(), output.finish())
    }

    private fun request(): AgentExecutionRequest = AgentExecutionRequest(
        objective = "repair the captured source",
        workspaceRoots = listOf(AgentWorkspaceRoot("project", ACP_CAPTURED_REPAIR_WORKSPACE)),
        accessPolicy = AgentAccessPolicy(
            listOf(
                AgentPathRule(
                    AgentWorkspacePath("project", "src/module.c"),
                    setOf(AgentOperation.READ_FILE, AgentOperation.WRITE_FILE),
                ),
            ),
        ),
    )
}
