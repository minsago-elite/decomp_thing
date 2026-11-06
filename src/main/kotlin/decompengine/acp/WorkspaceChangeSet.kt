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
    fun classify(
        changes: Collection<WorkspaceSnapshotChange>,
        checkpoint: () -> Unit = {},
    ): WorkspaceChangeSet {
        val ordered = changes.sortedWith(
            compareBy<WorkspaceSnapshotChange>({ it.source.rootId }, { it.source.relativePath }),
        )
        require(ordered.map { it.source }.distinct().size == ordered.size) {
            "workspace change set contains duplicate paths"
        }

        val deletedByContent = mutableMapOf<ContentIdentity, MutableList<WorkspaceSnapshotChange>>()
        val createdByContent = mutableMapOf<ContentIdentity, MutableList<WorkspaceSnapshotChange>>()
        ordered.forEachIndexed { index, change ->
            if (index % CHECKPOINT_INTERVAL == 0) checkpoint()
            when (change.kind) {
                AgentFileChangeKind.DELETED -> {
                    val sha256 = change.beforeSha256
                    val size = change.beforeSizeBytes
                    if (sha256 != null && size != null) {
                        deletedByContent.getOrPut(ContentIdentity(sha256, size), ::mutableListOf).add(change)
                    }
                }
                AgentFileChangeKind.CREATED -> {
                    val sha256 = change.afterSha256
                    val size = change.afterSizeBytes
                    if (sha256 != null && size != null) {
                        createdByContent.getOrPut(ContentIdentity(sha256, size), ::mutableListOf).add(change)
                    }
                }
                AgentFileChangeKind.MODIFIED -> Unit
            }
        }

        val candidates = mutableListOf<AgentFileMoveCandidate>()
        deletedByContent.entries.sortedWith(compareBy({ it.key.sha256 }, { it.key.sizeBytes }))
            .forEachIndexed { index, (identity, deleted) ->
                if (index % CHECKPOINT_INTERVAL == 0) checkpoint()
                val created = createdByContent[identity]
                if (identity.sizeBytes > 0 && deleted.size == 1 && created?.size == 1) {
                    candidates += AgentFileMoveCandidate(
                        sourcePath = deleted.single().source,
                        destinationPath = created.single().source,
                        contentSha256 = identity.sha256,
                        sizeBytes = identity.sizeBytes,
                    )
                }
            }
        candidates.sortWith(compareBy(
            { it.sourcePath.rootId }, { it.sourcePath.relativePath },
            { it.destinationPath.rootId }, { it.destinationPath.relativePath },
        ))

        val result = ordered.mapIndexed { index, change ->
            if (index % CHECKPOINT_INTERVAL == 0) checkpoint()
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

    private const val CHECKPOINT_INTERVAL = 64
    private data class ContentIdentity(val sha256: String, val sizeBytes: Long)
}
