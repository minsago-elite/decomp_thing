package decompengine.acp

import decompengine.agent.AgentFileChange
import decompengine.agent.AgentFileChangeKind
import decompengine.agent.AgentFileMoveCandidate
import decompengine.agent.AgentWorkspacePath

internal data class WorkspaceSnapshotChange(
    val source: AgentWorkspacePath,
    val kind: AgentFileChangeKind,
    val beforeSha256: String?,
    val afterSha256: String?,
    val beforeSizeBytes: Long?,
    val afterSizeBytes: Long?,
)

/** Exact path changes plus only unambiguous, non-empty content-matched move candidates. */
internal data class WorkspaceChangeSet(
    val changes: List<AgentFileChange>,
    val moveCandidates: List<AgentFileMoveCandidate>,
)

internal object WorkspaceChangeSetClassifier {
    fun classify(changes: Collection<WorkspaceSnapshotChange>): WorkspaceChangeSet {
        val ordered = changes.sortedWith(
            compareBy<WorkspaceSnapshotChange>({ it.source.rootId }, { it.source.relativePath }),
        )
        require(ordered.map { it.source }.distinct().size == ordered.size) {
            "workspace change set contains duplicate paths"
        }

        val deletedByContent = ordered.asSequence()
            .filter {
                it.kind == AgentFileChangeKind.DELETED && it.beforeSha256 != null && it.beforeSizeBytes != null
            }
            .groupBy { ContentIdentity(it.beforeSha256!!, it.beforeSizeBytes!!) }
        val createdByContent = ordered.asSequence()
            .filter {
                it.kind == AgentFileChangeKind.CREATED && it.afterSha256 != null && it.afterSizeBytes != null
            }
            .groupBy { ContentIdentity(it.afterSha256!!, it.afterSizeBytes!!) }

        val candidates = deletedByContent.keys.intersect(createdByContent.keys)
            .asSequence()
            .filter { it.sizeBytes > 0 }
            .filter { identity ->
                deletedByContent.getValue(identity).size == 1 && createdByContent.getValue(identity).size == 1
            }
            .map { identity ->
                AgentFileMoveCandidate(
                    sourcePath = deletedByContent.getValue(identity).single().source,
                    destinationPath = createdByContent.getValue(identity).single().source,
                    contentSha256 = identity.sha256,
                    sizeBytes = identity.sizeBytes,
                )
            }
            .sortedWith(compareBy(
                { it.sourcePath.rootId }, { it.sourcePath.relativePath },
                { it.destinationPath.rootId }, { it.destinationPath.relativePath },
            ))
            .toList()

        val result = ordered.map { change ->
            AgentFileChange(
                path = change.source,
                kind = change.kind,
                beforeSha256 = change.beforeSha256,
                afterSha256 = change.afterSha256,
                sizeBytes = change.afterSizeBytes,
            )
        }
        return WorkspaceChangeSet(result, candidates)
    }

    private data class ContentIdentity(val sha256: String, val sizeBytes: Long)
}
