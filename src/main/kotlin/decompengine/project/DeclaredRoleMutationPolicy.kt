package decompengine.project

import decompengine.agent.AgentMutationAuthority
import decompengine.agent.AgentMutationContentKind
import decompengine.agent.AgentMutationGrant
import decompengine.agent.AgentOperation
import decompengine.agent.AgentWorkspacePath

/** Builds an immutable, request-bound mutation restriction from trusted profile and workflow inputs. */
internal object DeclaredRoleMutationPolicy {
    private val protectedRoles = setOf(
        ProjectFileRole.EVIDENCE,
        ProjectFileRole.BEHAVIOR_EVIDENCE,
        ProjectFileRole.BUILD_ARTIFACT,
    )

    fun forDeclaredPaths(
        profile: ReconstructionProfile,
        rootId: String,
        ownerId: String,
        operationsByPath: Map<String, Set<AgentOperation>>,
        requiredOwnershipRoles: Set<ProjectFileRole>,
        maximumBytes: Long,
        policyId: String,
    ): AgentMutationAuthority {
        require(operationsByPath.isNotEmpty()) { "declared mutation authority must own at least one path" }
        require(maximumBytes > 0) { "declared mutation byte limit must be positive" }
        val grants = operationsByPath.toSortedMap().map { (relativePath, operations) ->
            requireMutablePath(relativePath)
            val declaration = profile.layout.declarationForPath(relativePath)
            require(declaration.roles.none { it in protectedRoles }) {
                "declared role is immutable for mutation: ${declaration.id}"
            }
            require(ProjectFileRole.EDITABLE in declaration.roles &&
                declaration.contentKind == ProjectContentKind.UTF8_TEXT) {
                "mutation requires an editable UTF-8 declaration: ${declaration.id}"
            }
            require(declaration.roles.any { it in requiredOwnershipRoles }) {
                "declaration is outside workflow ownership: ${declaration.id}"
            }
            AgentMutationGrant(
                path = AgentWorkspacePath(rootId, relativePath),
                operations = operations,
                ownerId = ownerId,
                profileSha256 = profile.sha256,
                declarationId = declaration.id,
                roles = declaration.roles.map(ProjectFileRole::wireName),
                contentKind = AgentMutationContentKind.UTF8_TEXT,
                maximumBytes = minOf(maximumBytes, profile.budgets.archiveMaximumFileBytes),
            )
        }
        return AgentMutationAuthority(policyId, ownerId, profile.sha256, grants)
    }

    /** Explicit namespace mapping for MVP's virtual staging files, which are not profile paths. */
    fun forMvpStagedTarget(profile: ReconstructionProfile, ownerId: String, stagedPath: String,
                           maximumBytes: Long, policyId: String): AgentMutationAuthority {
        requireMutablePath(stagedPath)
        require(stagedPath in MVP_STAGED_MUTATION_TARGETS) { "MVP staged target is not declared: $stagedPath" }
        return AgentMutationAuthority(
            policyId = policyId,
            ownerId = ownerId,
            profileSha256 = profile.sha256,
            grants = listOf(AgentMutationGrant(
                path = AgentWorkspacePath("project", stagedPath),
                operations = setOf(AgentOperation.WRITE_FILE),
                ownerId = ownerId,
                profileSha256 = profile.sha256,
                declarationId = if (stagedPath == "decompiled.c") "mvp-reconstruction-target" else "mvp-patch-target",
                roles = setOf("editable", "utf8-text", "workflow-owned-staging"),
                contentKind = AgentMutationContentKind.UTF8_TEXT,
                maximumBytes = minOf(maximumBytes, profile.budgets.archiveMaximumFileBytes),
            )),
        )
    }

    /** Narrow synthetic declaration for the explicitly test-only host-process repair adapter. */
    fun forTestOnlyPaths(profileSha256: String, rootId: String, ownerId: String,
                         operationsByPath: Map<String, Set<AgentOperation>>, maximumBytes: Long): AgentMutationAuthority {
        require(profileSha256.matches(Regex("[0-9a-f]{64}")))
        val grants = operationsByPath.toSortedMap().map { (path, operations) ->
            requireMutablePath(path)
            AgentMutationGrant(
                AgentWorkspacePath(rootId, path), operations, ownerId, profileSha256,
                "test-owned-source", setOf("test-only-editable", "utf8-text"),
                AgentMutationContentKind.UTF8_TEXT, maximumBytes,
            )
        }
        return AgentMutationAuthority("test-only-role-policy-v1", ownerId, profileSha256, grants)
    }

    private fun requireMutablePath(path: String) {
        val segments = path.split('/')
        require(segments.none { segment ->
            segment == ".git" || segment.endsWith(".repair") ||
                segment in setOf("manifest.json", "checkpoint.json")
        }) { "revision-control and checkpoint paths are immutable" }
    }

    private val MVP_STAGED_MUTATION_TARGETS = setOf("decompiled.c", "patched.c")
}
