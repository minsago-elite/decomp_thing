package decompengine.acp

import com.agentclientprotocol.protocol.AcpExpectedError
import decompengine.agent.AgentAccessPolicy
import decompengine.agent.AgentExecutionRequest
import decompengine.agent.AgentOperation
import decompengine.agent.AgentPathRule
import decompengine.agent.AgentWorkspacePath
import decompengine.agent.AgentWorkspaceRoot
import java.nio.file.Files
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlinx.coroutines.runBlocking

/** Runs in a disposable user+mount namespace launched by [AcpFilesystemBrokerTest]. */
internal object AcpFilesystemMountProbe {
    @JvmStatic
    fun main(args: Array<String>) {
        check(command("mount", "--make-rprivate", "/") == 0) { "could not privatize mount namespace" }
        val parent = createTempDirectory("acp-fs-mount-probe-").toAbsolutePath().normalize()
        val workspace = parent.resolve("workspace").createDirectories()
        val outsideDirectory = parent.resolve("outside-directory").createDirectories()
        val outsideDirectoryFile = outsideDirectory.resolve("secret.txt")
        outsideDirectoryFile.writeText("directory-secret\n")
        val mountedDirectory = workspace.resolve("mounted-directory").createDirectories()
        check(command("mount", "--bind", outsideDirectory.toString(), mountedDirectory.toString()) == 0) {
            "could not create directory bind mount"
        }

        val outsideFile = parent.resolve("outside-file.txt")
        outsideFile.writeText("file-secret\n")
        val mountedFile = workspace.resolve("mounted-file.txt")
        mountedFile.writeText("mount-placeholder\n")
        check(command("mount", "--bind", outsideFile.toString(), mountedFile.toString()) == 0) {
            "could not create file bind mount"
        }

        val policy = AgentAccessPolicy(
            listOf(
                AgentPathRule(
                    AgentWorkspacePath("project", "mounted-directory"),
                    setOf(AgentOperation.READ_FILE, AgentOperation.WRITE_FILE, AgentOperation.CREATE_FILE),
                    recursive = true,
                ),
                AgentPathRule(
                    AgentWorkspacePath("project", "mounted-file.txt"),
                    setOf(AgentOperation.READ_FILE, AgentOperation.WRITE_FILE),
                ),
            ),
        )
        val request = AgentExecutionRequest(
            objective = "reject bind-mount transitions",
            workspaceRoots = listOf(AgentWorkspaceRoot("project", workspace)),
            accessPolicy = policy,
        )
        val audit = AcpFilesystemAuditRecorder()
        AcpFilesystemBroker.open(request, AcpFilesystemLimits(), audit).use { broker ->
            expectDenied {
                broker.readTextFile(
                    "mount-probe",
                    mountedDirectory.resolve("secret.txt").toString(),
                    null,
                    null,
                )
            }
            expectDenied {
                broker.writeTextFile(
                    "mount-probe",
                    mountedDirectory.resolve("secret.txt").toString(),
                    "changed\n",
                )
            }
            expectDenied {
                broker.readTextFile("mount-probe", mountedFile.toString(), null, null)
            }
            expectDenied {
                broker.writeTextFile("mount-probe", mountedFile.toString(), "changed\n")
            }
        }

        check(outsideDirectoryFile.readText() == "directory-secret\n")
        check(outsideFile.readText() == "file-secret\n")
        check(audit.snapshot().map { it.reason } == List(4) { AcpFilesystemAuditReason.MOUNT_TRANSITION })
    }

    private fun command(vararg arguments: String): Int =
        ProcessBuilder(*arguments).inheritIO().start().waitFor()

    private fun expectDenied(block: suspend () -> Unit) {
        try {
            runBlocking { block() }
            error("mount transition was unexpectedly allowed")
        } catch (_: AcpExpectedError) {
            // Expected fail-closed callback response.
        }
    }
}
