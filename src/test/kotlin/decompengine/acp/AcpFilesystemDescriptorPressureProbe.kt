package decompengine.acp

import com.agentclientprotocol.protocol.AcpExpectedError
import decompengine.agent.AgentAccessPolicy
import decompengine.agent.AgentExecutionRequest
import decompengine.agent.AgentOperation
import decompengine.agent.AgentPathRule
import decompengine.agent.AgentWorkspacePath
import decompengine.agent.AgentWorkspaceRoot
import java.io.FileInputStream
import java.io.IOException
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.listDirectoryEntries
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlinx.coroutines.runBlocking

/** Runs with a low RLIMIT_NOFILE and forces the first real post-commit openat to return EMFILE. */
internal object AcpFilesystemDescriptorPressureProbe {
    @JvmStatic
    fun main(args: Array<String>) {
        verifyReserveAcquisitionFailureWithoutTemporary()
        verifyCreateRollback()
        verifyReplacementRollback()
    }

    private fun verifyReserveAcquisitionFailureWithoutTemporary() {
        val createWorkspace = createTempDirectory("acp-fs-emfile-reserve-create-").toAbsolutePath().normalize()
        val createTarget = createWorkspace.resolve("target.c")
        val createPressure = mutableListOf<FileInputStream>()
        val createAudit = AcpFilesystemAuditRecorder()
        AcpFilesystemBroker.open(
            request(createWorkspace, "target.c", AgentOperation.CREATE_FILE),
            AcpFilesystemLimits(),
            createAudit,
        ).use { broker ->
            exhaustDescriptors(createPressure)
            releaseDescriptors(createPressure, INSUFFICIENT_RESERVE_CAPACITY)
            expectDenied { broker.writeTextFile("emfile-reserve-create", createTarget.toString(), "new\n") }
        }
        createPressure.forEach { stream -> runCatching { stream.close() } }
        check(!createTarget.exists()) { "reserve acquisition failure created the target" }
        check(createWorkspace.listDirectoryEntries().none { it.fileName.toString().startsWith(".decomp-acp-") }) {
            "reserve acquisition failure left a create temporary"
        }
        check(createAudit.snapshot().single().reason == AcpFilesystemAuditReason.IO_FAILURE)

        val replaceWorkspace = createTempDirectory("acp-fs-emfile-reserve-replace-").toAbsolutePath().normalize()
        val replaceTarget = replaceWorkspace.resolve("target.c")
        replaceTarget.writeText("original\n")
        val replacePressure = mutableListOf<FileInputStream>()
        val replaceAudit = AcpFilesystemAuditRecorder()
        AcpFilesystemBroker.open(
            request(replaceWorkspace, "target.c", AgentOperation.WRITE_FILE),
            AcpFilesystemLimits(),
            replaceAudit,
        ).use { broker ->
            exhaustDescriptors(replacePressure)
            releaseDescriptors(replacePressure, INSUFFICIENT_RESERVE_CAPACITY)
            expectDenied { broker.writeTextFile("emfile-reserve-replace", replaceTarget.toString(), "new\n") }
        }
        replacePressure.forEach { stream -> runCatching { stream.close() } }
        check(replaceTarget.readText() == "original\n") { "reserve acquisition failure replaced the target" }
        check(replaceWorkspace.listDirectoryEntries().none { it.fileName.toString().startsWith(".decomp-acp-") }) {
            "reserve acquisition failure left a replacement temporary"
        }
        check(replaceAudit.snapshot().single().reason == AcpFilesystemAuditReason.IO_FAILURE)
    }

    private fun verifyCreateRollback() {
        val workspace = createTempDirectory("acp-fs-emfile-create-").toAbsolutePath().normalize()
        val target = workspace.resolve("target.c")
        val pressure = mutableListOf<FileInputStream>()
        val hook = AcpFilesystemRaceHook { stage, _ ->
            if (stage == AcpFilesystemRaceStage.AFTER_CREATE_RENAME) exhaustDescriptors(pressure)
        }
        val audit = AcpFilesystemAuditRecorder()
        val request = request(workspace, "target.c", AgentOperation.CREATE_FILE)

        AcpFilesystemBroker.open(request, AcpFilesystemLimits(), audit, hook).use { broker ->
            exhaustDescriptors(pressure)
            releaseDescriptors(pressure, PRECOMMIT_CAPACITY)
            expectDenied { broker.writeTextFile("emfile-create", target.toString(), "new\n") }
        }
        pressure.forEach { stream -> runCatching { stream.close() } }

        check(!target.exists()) { "EMFILE after create rename left the target installed" }
        check(workspace.listDirectoryEntries().none { it.fileName.toString().startsWith(".decomp-acp-") }) {
            "EMFILE after create rename left a transaction entry"
        }
        check(audit.snapshot().single().reason == AcpFilesystemAuditReason.IO_FAILURE)
    }

    private fun verifyReplacementRollback() {
        val workspace = createTempDirectory("acp-fs-emfile-replace-").toAbsolutePath().normalize()
        val target = workspace.resolve("target.c")
        target.writeText("original\n")
        val pressure = mutableListOf<FileInputStream>()
        val hook = AcpFilesystemRaceHook { stage, _ ->
            if (stage == AcpFilesystemRaceStage.AFTER_REPLACE_EXCHANGE) exhaustDescriptors(pressure)
        }
        val audit = AcpFilesystemAuditRecorder()
        val request = request(workspace, "target.c", AgentOperation.WRITE_FILE)

        AcpFilesystemBroker.open(request, AcpFilesystemLimits(), audit, hook).use { broker ->
            exhaustDescriptors(pressure)
            releaseDescriptors(pressure, PRECOMMIT_CAPACITY)
            expectDenied { broker.writeTextFile("emfile-replace", target.toString(), "new\n") }
        }
        pressure.forEach { stream -> runCatching { stream.close() } }

        check(target.readText() == "original\n") { "EMFILE after exchange did not restore the original" }
        check(workspace.listDirectoryEntries().none { it.fileName.toString().startsWith(".decomp-acp-") }) {
            "EMFILE after exchange left a transaction entry"
        }
        check(audit.snapshot().single().reason == AcpFilesystemAuditReason.IO_FAILURE)
    }

    private fun request(
        workspace: java.nio.file.Path,
        relativePath: String,
        operation: AgentOperation,
    ): AgentExecutionRequest = AgentExecutionRequest(
        objective = "force a post-commit descriptor allocation failure",
        workspaceRoots = listOf(AgentWorkspaceRoot("project", workspace)),
        accessPolicy = AgentAccessPolicy(
            listOf(
                AgentPathRule(
                    AgentWorkspacePath("project", relativePath),
                    setOf(operation),
                ),
            ),
        ),
    )

    private fun exhaustDescriptors(pressure: MutableList<FileInputStream>) {
        while (true) {
            try {
                pressure += FileInputStream("/dev/null")
            } catch (_: IOException) {
                return
            }
        }
    }

    private fun releaseDescriptors(pressure: MutableList<FileInputStream>, count: Int) {
        repeat(minOf(count, pressure.size)) {
            pressure.removeLast().close()
        }
    }

    private fun expectDenied(block: suspend () -> Unit) {
        try {
            runBlocking { block() }
            error("descriptor pressure operation was unexpectedly allowed")
        } catch (_: AcpExpectedError) {
            // Expected safe callback failure after the native openat returns EMFILE.
        }
    }

    private const val PRECOMMIT_CAPACITY = 24
    private const val INSUFFICIENT_RESERVE_CAPACITY = 4
}
