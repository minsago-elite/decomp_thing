package decompengine.project

import java.util.Collections

/** Exact workflow-accepted source transition authenticated from one release-complete ACP receipt. */
internal data class VerifiedCandidateAcpChange(
    val path: String,
    val kind: String,
    val beforeSha256: String?,
    val afterSha256: String?,
    val bytes: Long?,
) {
    init {
        requireNormalizedProjectPath(path, "verified ACP candidate change path")
        require(kind in setOf("created", "modified", "deleted")) {
            "verified ACP candidate change kind is invalid"
        }
        require(beforeSha256 == null || beforeSha256.matches(SHA256))
        require(afterSha256 == null || afterSha256.matches(SHA256))
        require(bytes == null || bytes >= 0L)
        require(
            when (kind) {
                "created" -> beforeSha256 == null && afterSha256 != null
                "modified" -> beforeSha256 != null && afterSha256 != null && beforeSha256 != afterSha256
                else -> beforeSha256 != null && afterSha256 == null
            },
        ) { "verified ACP candidate change transition is invalid" }
    }
}

/**
 * Immutable semantic projection produced only after the archive gate has authenticated the raw
 * receipt, its ACP session, and its workflow-specific accepted change set.
 */
internal class VerifiedCandidateAcpContribution(
    val workflow: String,
    val taskId: String,
    val receiptPath: String,
    val receiptBytes: Long,
    val receiptSha256: String,
    val requestSha256: String,
    val promptSha256: String,
    val resultChangesSha256: String,
    val session: VerifiedAcpAgentSessionFacts,
    changes: List<VerifiedCandidateAcpChange>,
    val parentSourceRevisionSha256: String?,
    val resultSourceRevisionSha256: String?,
) {
    val changes: List<VerifiedCandidateAcpChange> = Collections.unmodifiableList(changes.toList())

    init {
        require(workflow in setOf("reconstruction", "repair"))
        require(taskId.isNotBlank() && taskId.length <= 4096 && '\u0000' !in taskId)
        requireNormalizedProjectPath(receiptPath, "verified ACP candidate receipt path")
        require(receiptBytes > 0L)
        listOf(receiptSha256, requestSha256, promptSha256, resultChangesSha256).forEach { digest ->
            require(digest.matches(SHA256))
        }
        require(changes.isNotEmpty())
        require(changes.map(VerifiedCandidateAcpChange::path) ==
            changes.map(VerifiedCandidateAcpChange::path).distinct().sorted()
        ) { "verified ACP candidate changes must be unique and sorted" }
        require(parentSourceRevisionSha256 == null || parentSourceRevisionSha256.matches(SHA256))
        require(resultSourceRevisionSha256 == null || resultSourceRevisionSha256.matches(SHA256))
        require((parentSourceRevisionSha256 == null) == (resultSourceRevisionSha256 == null))
        require(workflow == "repair" || parentSourceRevisionSha256 == null)
    }
}

internal class VerifiedCandidateArchiveSourceLineage(
    val profileId: String,
    val profileSha256: String,
    val inputSha256: String,
    val sourceTreeManifestBytes: Long,
    val sourceTreeManifestSha256: String,
    val sourceRevision: BuildSourceRevision,
    val repairGraphHeadId: String?,
    val repairGraphHeadRevisionSha256: String?,
    acceptedAcpContributions: List<VerifiedCandidateAcpContribution>,
) {
    val acceptedAcpContributions: List<VerifiedCandidateAcpContribution> =
        Collections.unmodifiableList(acceptedAcpContributions.toList())

    init {
        require(profileId.isNotBlank() && profileId.length <= 128)
        require(profileSha256.matches(SHA256) && inputSha256.matches(SHA256))
        require(sourceTreeManifestBytes > 0L && sourceTreeManifestSha256.matches(SHA256))
        require(sourceRevision.sha256.matches(SHA256) && sourceRevision.inputs.isNotEmpty())
        require((repairGraphHeadId == null) == (repairGraphHeadRevisionSha256 == null))
        require(repairGraphHeadRevisionSha256 == null || repairGraphHeadRevisionSha256.matches(SHA256))
        require(this.acceptedAcpContributions.map(VerifiedCandidateAcpContribution::receiptPath).distinct().size ==
            this.acceptedAcpContributions.size
        ) { "verified ACP candidate receipt paths must be unique" }
        require(this.acceptedAcpContributions.map { it.workflow to it.taskId }.distinct().size ==
            this.acceptedAcpContributions.size
        ) { "verified ACP candidate workflow tasks must be unique" }
    }
}

internal data class VerifiedCandidateArchiveLineage(
    val archiveManifestBytes: Long,
    val archiveManifestSha256: String,
    val source: VerifiedCandidateArchiveSourceLineage,
) {
    init {
        require(archiveManifestBytes > 0L && archiveManifestSha256.matches(SHA256))
    }
}

private val SHA256 = Regex("[0-9a-f]{64}")
