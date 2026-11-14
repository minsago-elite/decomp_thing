package decompengine.project

import decompengine.agent.AgentAccessPolicy
import decompengine.agent.AgentExecutionRequest
import decompengine.agent.AgentExecutionRequestBinding
import decompengine.agent.AgentMutationAuthority
import decompengine.agent.AgentMutationContentKind
import decompengine.agent.AgentMutationGrant
import decompengine.agent.AgentOperation
import decompengine.agent.AgentPathRule
import decompengine.agent.AgentWorkspacePath
import decompengine.agent.AgentWorkspaceRoot
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class DeclaredRoleMutationPolicyTest {
    @Test
    fun `reconstruction authority is exact and request bound`() {
        val profile = GeneratedCMakeReconstructionProfile.descriptor
        val operations = setOf(AgentOperation.WRITE_FILE, AgentOperation.CREATE_FILE)
        val authority = DeclaredRoleMutationPolicy.forDeclaredPaths(
            profile, "project", "module-reconstruction:${profile.id}:parser",
            mapOf("src/modules/parser.c" to operations),
            setOf(ProjectFileRole.MODULE_IMPLEMENTATION, ProjectFileRole.ENTRYPOINT_IMPLEMENTATION),
            1024, "declared-role-reconstruction-v1",
        )
        val target = AgentWorkspacePath("project", "src/modules/parser.c")
        val policy = AgentAccessPolicy(listOf(AgentPathRule(target, operations)), mutationAuthority = authority)

        assertTrue(policy.allowsMutation(target, AgentOperation.CREATE_FILE, 8, true))
        assertTrue(policy.allowsMutation(target, AgentOperation.WRITE_FILE, 8, true))
        assertFalse(policy.allowsMutation(target, AgentOperation.DELETE_FILE))
        assertFalse(policy.allowsMutation(target, AgentOperation.WRITE_FILE, 1025, true))
        assertFalse(policy.allowsMutation(target, AgentOperation.WRITE_FILE, 8, false))
        assertFalse(policy.allowsMutation(AgentWorkspacePath("project", "src/modules/other.c"), AgentOperation.WRITE_FILE))
        val narrowPathPolicy = AgentAccessPolicy(emptyList(), emptySet(), authority)
        assertFalse(narrowPathPolicy.allowsMutation(target, AgentOperation.WRITE_FILE, 8, true))

        val root = AgentWorkspaceRoot("project", Path.of("/tmp/declared-role-project"))
        val request = AgentExecutionRequest("reconstruct parser", listOf(root), accessPolicy = policy)
        val withoutAuthority = AgentExecutionRequest(
            "reconstruct parser", listOf(root), accessPolicy = AgentAccessPolicy(listOf(AgentPathRule(target, operations))),
        )
        assertNotEquals(
            AgentExecutionRequestBinding.capture(withoutAuthority).accessPolicySha256,
            AgentExecutionRequestBinding.capture(request).accessPolicySha256,
        )
    }

    @Test
    fun `immutable and undeclared declarations cannot be granted`() {
        val profile = GeneratedCMakeReconstructionProfile.descriptor
        fun authority(path: String) = DeclaredRoleMutationPolicy.forDeclaredPaths(
            profile, "project", "test-owner", mapOf(path to setOf(AgentOperation.WRITE_FILE)),
            setOf(ProjectFileRole.BUILD_INPUT, ProjectFileRole.MODULE_IMPLEMENTATION), 1024,
            "declared-role-test-v1",
        )

        assertFalse(runCatching { authority("reports/modules/parser.json") }.isSuccess)
        assertFalse(runCatching { authority("undeclared.c") }.isSuccess)
        assertFalse(runCatching { authority(".git/config") }.isSuccess)
        assertFalse(runCatching { authority("src/modules/parser.c.repair") }.isSuccess)
    }

    @Test
    fun `conflicting immutable role dominates editable role`() {
        val base = GeneratedCMakeReconstructionProfile.descriptor
        val conflicting = ReconstructionProfile(
            schemaVersion = ReconstructionProfile.CURRENT_SCHEMA_VERSION,
            id = "mutation-test-profile",
            layout = ProjectLayoutProfile(
                ProjectLayoutProfile.CURRENT_SCHEMA_VERSION,
                listOf(ProjectFileDeclaration(
                    "conflicting-source", "src.c",
                    setOf(ProjectFileRole.EDITABLE, ProjectFileRole.BUILD_INPUT, ProjectFileRole.EVIDENCE),
                    ProjectContentKind.UTF8_TEXT,
                )),
            ),
            budgets = base.budgets,
        )
        assertFalse(runCatching {
            DeclaredRoleMutationPolicy.forDeclaredPaths(
                conflicting, "project", "owner", mapOf("src.c" to setOf(AgentOperation.WRITE_FILE)),
                setOf(ProjectFileRole.BUILD_INPUT), 64, "declared-role-test-v1",
            )
        }.isSuccess)
    }

    @Test
    fun `MVP staged mapping grants only its explicit target`() {
        val profile = GeneratedCMakeReconstructionProfile.descriptor
        val authority: AgentMutationAuthority = DeclaredRoleMutationPolicy.forMvpStagedTarget(
            profile, "mvp-task-1", "decompiled.c", 512, "declared-role-mvp-staging-v1",
        )
        val target = AgentWorkspacePath("project", "decompiled.c")
        assertTrue(authority.allowsContent(target, AgentOperation.WRITE_FILE, 128, true))
        assertFalse(authority.allowsContent(AgentWorkspacePath("project", "ghidra_decompiled.c"), AgentOperation.WRITE_FILE, 1, true))
        assertFalse(authority.allowsContent(target, AgentOperation.WRITE_FILE, 513, true))
        assertFalse(authority.allowsContent(target, AgentOperation.WRITE_FILE, 128, false))
    }

    @Test
    fun `authority data is defensively immutable and operation limited`() {
        val roles = mutableSetOf("editable")
        val operations = mutableSetOf(AgentOperation.WRITE_FILE)
        val path = AgentWorkspacePath("project", "src/modules/parser.c")
        val grant = AgentMutationGrant(
            path, operations, "owner", "a".repeat(64), "module-implementation", roles,
            AgentMutationContentKind.UTF8_TEXT, 100,
        )
        val authority = AgentMutationAuthority("declared-role-test-v1", "owner", "a".repeat(64), listOf(grant))
        roles += "evidence"
        operations += AgentOperation.DELETE_FILE
        assertFalse(authority.allows(path, AgentOperation.DELETE_FILE))
        assertTrue(authority.allows(path, AgentOperation.WRITE_FILE))
    }

    @Test
    fun `deletion is an explicit independent grant and is not inferred from editability`() {
        val profile = GeneratedCMakeReconstructionProfile.descriptor
        val deleteAuthority = DeclaredRoleMutationPolicy.forDeclaredPaths(
            profile, "project", "owner", mapOf("src/modules/parser.c" to setOf(AgentOperation.DELETE_FILE)),
            setOf(ProjectFileRole.MODULE_IMPLEMENTATION), 1024, "declared-role-delete-test-v1",
        )
        val path = AgentWorkspacePath("project", "src/modules/parser.c")
        assertTrue(deleteAuthority.allows(path, AgentOperation.DELETE_FILE))
        assertTrue(deleteAuthority.allowsContent(path, AgentOperation.DELETE_FILE, 8, true))
        assertFalse(deleteAuthority.allowsContent(path, AgentOperation.DELETE_FILE, 8, false))
        assertFalse(deleteAuthority.allows(path, AgentOperation.WRITE_FILE))
    }

    @Test
    fun `built in Make and Ninja profiles produce the same narrow implementation grant`() {
        for (profile in listOf(
            GeneratedCMakeReconstructionProfile.descriptor,
            GeneratedCNinjaReconstructionProfile.descriptor,
        )) {
            val target = "src/modules/parser.c"
            val authority = DeclaredRoleMutationPolicy.forDeclaredPaths(
                profile, "project", "module-reconstruction:${profile.id}:parser",
                mapOf(target to setOf(AgentOperation.WRITE_FILE, AgentOperation.CREATE_FILE)),
                setOf(ProjectFileRole.MODULE_IMPLEMENTATION), 4096, "declared-role-reconstruction-v1",
            )
            assertTrue(authority.allows(AgentWorkspacePath("project", target), AgentOperation.CREATE_FILE))
            assertFalse(authority.allows(AgentWorkspacePath("project", "Makefile"), AgentOperation.WRITE_FILE))
        }
    }
}
