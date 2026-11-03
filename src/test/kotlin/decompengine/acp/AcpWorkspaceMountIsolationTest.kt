package decompengine.acp

import decompengine.agent.AgentWorkspaceRoot
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class AcpWorkspaceMountIsolationTest {
    @Test
    fun `runtime aliases cannot expose a workspace file directory or ancestor`() = withDirectory { parent ->
        val workspace = Files.createDirectory(parent.resolve("project"))
        val header = Files.writeString(workspace.resolve("private.h"), "private interface")
        val roots = listOf(AgentWorkspaceRoot("project", workspace))
        for (source in listOf(header, workspace, parent)) {
            val failure = assertFailsWith<IllegalArgumentException> {
                requireAgentRuntimeMountsExcludeWorkspace(roots, listOf(mount(source)))
            }
            assertTrue(failure.message.orEmpty().contains("must not overlap"))
        }
    }

    @Test
    fun `every declared workspace is excluded while disjoint runtime siblings remain allowed`() = withDirectory { parent ->
        val first = Files.createDirectory(parent.resolve("project"))
        val second = Files.createDirectory(parent.resolve("another-project"))
        val runtime = Files.createDirectory(parent.resolve("project-runtime"))
        val roots = listOf(AgentWorkspaceRoot("first", first), AgentWorkspaceRoot("second", second))
        requireAgentRuntimeMountsExcludeWorkspace(roots, listOf(mount(runtime)))
        assertFailsWith<IllegalArgumentException> {
            requireAgentRuntimeMountsExcludeWorkspace(roots, listOf(mount(second)))
        }
    }

    @Test
    fun `symbolic aliases cannot disguise runtime sources or workspace roots`() = withDirectory { parent ->
        val workspace = Files.createDirectory(parent.resolve("project"))
        val header = Files.writeString(workspace.resolve("private.h"), "private interface")
        val alias = Files.createSymbolicLink(parent.resolve("alias"), workspace)
        assertFailsWith<IllegalArgumentException> {
            requireAgentRuntimeMountsExcludeWorkspace(
                listOf(AgentWorkspaceRoot("project", workspace)), listOf(mount(alias.resolve("private.h"))),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            requireAgentRuntimeMountsExcludeWorkspace(
                listOf(AgentWorkspaceRoot("project", alias)), listOf(mount(header)),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            requireAgentRuntimeMountsExcludeWorkspace(
                listOf(AgentWorkspaceRoot("project", alias.resolve("virtual-child"))), listOf(mount(header)),
            )
        }
    }

    @Test
    fun `namespace-only workspaces need no host directory`() = withDirectory { parent ->
        val runtime = Files.writeString(parent.resolve("runtime"), "runtime executable")
        val roots = listOf(AgentWorkspaceRoot("captured", parent.resolve("absent/virtual-project")))
        requireAgentRuntimeMountsExcludeWorkspace(roots, listOf(mount(runtime)))
        assertTrue(Files.notExists(roots.single().path))
    }

    private fun mount(source: Path) = AcpSandboxReadOnlyMount(source, Path.of("/opt/agent-runtime-alias"))

    private fun withDirectory(action: (Path) -> Unit) {
        val scratch = Path.of("build", "test-scratch").toAbsolutePath().normalize()
        Files.createDirectories(scratch)
        val directory = Files.createTempDirectory(scratch, "acp-workspace-mount-")
        try {
            action(directory)
        } finally {
            Files.walk(directory).use { paths ->
                paths.sorted(Comparator.reverseOrder()).forEach(Files::delete)
            }
        }
    }
}
