package decompengine.git

/**
 * Opaque identities and versions shared by reads and mutation guards. A mutation's guards must
 * name exactly the versions a read reported, so both sides compute them here.
 */
object GitWorkspaceVersions {
    private fun digest(prefix: String, text: String) = prefix + GitStorage.sha256(text).take(32)

    fun refId(repositoryId: String, name: String) = digest("ref_", "$repositoryId\n$name")
    fun refVersion(name: String, objectId: String) = digest("ref_v_", "$name\n$objectId")

    /** HEAD's branch first, then the remaining observed refs, bounded to 200. */
    fun refs(observation: GitWorkspaceObservation): List<GitRefObservation> {
        val head = observation.head
        val headRef = if (head.state == GitHeadState.ATTACHED) GitRefObservation(checkNotNull(head.refName), checkNotNull(head.objectId)) else null
        return (listOfNotNull(headRef) + observation.refs.filter { it != headRef }).take(200)
    }

    fun repositoryVersion(record: GitRepositoryRecord, observation: GitWorkspaceObservation): String =
        digest("repository_v_", "${record.repositoryId}\n${record.operationId}\n${observation.refsTruncated}\n" +
            refs(observation).joinToString("") { "${it.name}\u0000${it.objectId}\n" })

    /** Mutation guards bind exact status-path bytes/modes as well as the read-only stat cursor. */
    fun worktreeVersion(observation: GitWorkspaceObservation): String = digest("worktree_v_",
        observation.statusDigest + "\n" + observation.contentFingerprints.entries.joinToString("") { (path, content) ->
            "${GitStorage.sha256(path.bytes)}\u0000$content\n"
        })

    fun headRefId(record: GitRepositoryRecord, observation: GitWorkspaceObservation): String? =
        observation.head.takeIf { it.state == GitHeadState.ATTACHED }?.refName?.let { refId(record.repositoryId, it) }
}
