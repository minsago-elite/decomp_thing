package decompengine.git

import decompengine.git.GitStorage.hex
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.FileAlreadyExistsException
import java.nio.file.FileVisitResult
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.SimpleFileVisitor
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardOpenOption.WRITE
import java.nio.file.attribute.BasicFileAttributes
import java.security.MessageDigest
import java.time.Duration
import java.time.Instant

/** Versions and objects a mutation was reviewed against; all are rechecked under the operation lease. */
data class GitGuards(
    val repositoryVersion: String,
    val worktreeVersion: String,
    val expectedHeadObjectId: String?,
    val expectedRefId: String?,
    val expectedRefObjectId: String?,
) {
    val text: String get() = "$repositoryVersion\n$worktreeVersion\n${expectedHeadObjectId ?: "-"}\n${expectedRefId ?: "-"}\n${expectedRefObjectId ?: "-"}"
}

/** Stage or unstage exactly the selected status entries. */
data class GitStageRequest(val worktreeId: String, val guards: GitGuards, val fileIds: List<String>, val stage: Boolean) : GitRepositoryRequest {
    override val action get() = if (stage) GitOperationAction.STAGE else GitOperationAction.UNSTAGE
    override val digest get() = GitStorage.sha256("${action.wireName}\n$worktreeId\n${guards.text}\n${fileIds.joinToString(",")}\n")
}

/** Commit exactly the reviewed staged set with the server identity. */
data class GitCommitRequest(val worktreeId: String, val guards: GitGuards, val fileIds: List<String>, val message: String) : GitRepositoryRequest {
    override val action get() = GitOperationAction.COMMIT
    override val digest get() = GitStorage.sha256("git.commit\n$worktreeId\n${guards.text}\n${fileIds.joinToString(",")}\n" +
        GitStorage.sha256(message) + "\n")
}

/**
 * A commit operation read back from its durable record. The message is used only by the process
 * that admitted it; the record retains its digest so a keyed replay still matches exactly.
 */
data class GitRetainedCommit(val worktreeId: String, val guards: GitGuards, val fileIds: List<String>, val messageSha256: String) : GitRepositoryRequest {
    override val action get() = GitOperationAction.COMMIT
    override val digest get() = GitStorage.sha256("git.commit\n$worktreeId\n${guards.text}\n${fileIds.joinToString(",")}\n$messageSha256\n")
}

/**
 * Durable commit-to-revision binding (#577). Written only when the commit tree holds exactly the
 * copied bytes of the repository's candidate snapshot; acceptance is derived from canonical job
 * evidence at read time and never stored here.
 */
data class GitMappingRecord(
    val repositoryId: String,
    val objectId: String,
    val revisionId: String,
    val sourceSha256: String,
    val recordedAt: Instant,
    /** Whether uncommitted changes remained in the work tree when the commit was recorded. */
    val worktreeDirty: Boolean,
)

data class GitMappingView(val record: GitMappingRecord, val acceptance: String, val acceptanceArtifactId: String?) {
    init { require(acceptance in setOf("not-evaluated", "accepted", "rejected", "unknown") && (acceptance != "accepted" || acceptanceArtifactId != null)) }
}

/** Canonical acceptance for a revision and its source digest, from the job's own evidence. */
fun interface GitAcceptanceResolver {
    /** Returns the acceptance state and, when accepted, its evidence artifact identity. */
    fun acceptance(jobId: String, revisionId: String, sourceSha256: String): Pair<String, String?>
}

class GitOperationRefusal(val code: String, message: String) : Exception(message)

internal object GitWorkspaceMutations {
    private val COMMIT_LIMITS = GitExecutionLimits(Duration.ofMinutes(2), 64 * 1024, 64 * 1024)
    const val MAX_MESSAGE = 8192

    fun refuse(code: String, message: String): Nothing = throw GitOperationRefusal(code, message)

    /** Guards against the current observation; a mismatch means the reviewed state is gone. */
    fun checkGuards(record: GitRepositoryRecord, observation: GitWorkspaceObservation, guards: GitGuards) {
        if (GitWorkspaceVersions.repositoryVersion(record, observation) != guards.repositoryVersion ||
            observation.head.objectId != guards.expectedHeadObjectId
        ) refuse("REF_CHANGED", "HEAD or the repository's refs changed since this action was reviewed. Read the current state first.")
        if (guards.expectedRefId != null) {
            val headRef = GitWorkspaceVersions.headRefId(record, observation)
            if (headRef != guards.expectedRefId || observation.head.objectId != guards.expectedRefObjectId) {
                refuse("REF_CHANGED", "The reviewed branch no longer names the expected commit. Read the current state first.")
            }
        } else if (guards.expectedRefObjectId != null) refuse("VALIDATION_FAILED", "A ref object guard needs its ref identity.")
        if (GitWorkspaceVersions.worktreeVersion(observation) != guards.worktreeVersion) {
            refuse("WORKTREE_CHANGED", "The work tree or index changed since this action was reviewed. Read the current status first.")
        }
    }

    /** Map reviewed file identities to the current status entries, refusing anything not selectable. */
    fun select(record: GitRepositoryRecord, observation: GitWorkspaceObservation, fileIds: List<String>, stage: Boolean): List<GitStatusEntry> {
        if (!observation.status.complete) refuse("STATUS_INCOMPLETE", "The status is too large to review completely; selection is unavailable.")
        // One path can have two records: a staged deletion and an untracked replacement share a
        // file identity. Resolve each selection against the record the action applies to.
        val byId = observation.status.entries.groupBy { it.path.fileId(record.worktreeId) }
        fun applies(entry: GitStatusEntry) = if (stage) entry.untracked || entry.unstaged != GitIndexChange.NONE else entry.staged != GitIndexChange.NONE
        return fileIds.map { id ->
            val records = byId[id] ?: refuse("SELECTION_CHANGED", "A selected file is no longer in the current status.")
            val entry = records.firstOrNull { !it.ignored && applies(it) } ?: records.first()
            if (entry.ignored) refuse("EXCLUDED_PATH", "A selected file is excluded by the source-only tracking policy and cannot be staged.")
            if (entry.submodule) refuse("EXCLUDED_PATH", "Submodule entries are not staged by the workbench.")
            if (entry.path.exact == null || (entry.originalPath != null && entry.originalPath.exact == null)) {
                refuse("EXCLUDED_PATH", "A selected file name is not valid UTF-8 and cannot be staged by the workbench.")
            }
            if (entry.conflict != null) refuse("CONFLICTED", "Resolve conflicted files in the work tree before staging them.")
            if (!applies(entry)) refuse("NOTHING_SELECTED", if (stage) "A selected file has no unstaged change." else "A selected file has no staged change.")
            entry
        }.also { selected -> refuseOverlap(observation, selected) }
    }

    /**
     * Pathspecs match descendants: a selected path (or a rename's original path) that is now a
     * directory holding other tracked or staged entries would act on those too. Refuse instead.
     */
    private fun refuseOverlap(observation: GitWorkspaceObservation, selected: List<GitStatusEntry>) {
        val chosen = selected.toSet()
        val prefixes = selected.flatMap { listOfNotNull(it.path.exact, it.originalPath?.exact) }.map { "$it/" }
        val overlapping = observation.status.entries.any { entry ->
            entry !in chosen && !entry.ignored && !entry.untracked && listOfNotNull(entry.path.exact, entry.originalPath?.exact).any { path ->
                prefixes.any { path.startsWith(it) }
            }
        }
        if (overlapping) refuse("SELECTION_OVERLAP", "A selected path is now a directory containing other changes. Select those entries explicitly or resolve the overlap first.")
    }

    /** The reviewed selection must be exactly today's staged set: nothing swept in, nothing left out. */
    fun requireStagedSet(record: GitRepositoryRecord, observation: GitWorkspaceObservation, fileIds: List<String>) {
        // A truncated status can hide staged files beyond its bound; never commit an unreviewable index.
        if (!observation.status.complete) refuse("STATUS_INCOMPLETE", "The status is too large to review completely; the staged set cannot be confirmed.")
        if (observation.status.entries.any { it.conflict != null }) refuse("CONFLICTED", "Resolve conflicted files before committing.")
        val staged = observation.status.entries.filter { it.staged != GitIndexChange.NONE }.map { it.path.fileId(record.worktreeId) }.toSet()
        if (staged.isEmpty()) refuse("NOTHING_TO_COMMIT", "No changes are staged.")
        if (staged != fileIds.toSet()) refuse("INDEX_CHANGED", "The staged files differ from the reviewed selection. Review the staged diff again.")
    }

    fun validateMessage(message: String) {
        if (message.isBlank() || message.length > MAX_MESSAGE || message.any { it.isISOControl() && it != '\n' && it != '\t' }) {
            refuse("VALIDATION_FAILED", "A commit message must be 1-8192 characters of text without control characters other than newlines and tabs.")
        }
    }

    /** Paths go through NUL-separated standard input, so no selection size meets the argv bound. */
    private fun pathspecs(paths: List<String>): ByteArray = paths.joinToString("") { "$it\u0000" }.toByteArray(Charsets.UTF_8)
    private val FROM_STDIN = listOf("--pathspec-from-file=-", "--pathspec-file-nul")

    /**
     * A pathspec is not an index-entry identity: `add` of a deleted file whose name is now a
     * directory would also add everything beneath it. Deletions are therefore staged with an
     * index-only `rm --cached` (which never recurses), and every other path must still be a
     * regular file or link, never a directory.
     */
    fun stage(runner: GitCommandRunner, gitDir: Path, workTree: Path, entries: List<GitStatusEntry>) {
        val (deletions, others) = entries.partition { it.unstaged == GitIndexChange.DELETED }
        for (entry in others) {
            if (Files.isDirectory(workTree.resolve(checkNotNull(entry.path.exact)), NOFOLLOW_LINKS)) {
                refuse("SELECTION_CHANGED", "A selected path is now a directory; read the current status before staging.")
            }
        }
        if (deletions.isNotEmpty()) runner.run(GitInvocation("rm", listOf("--cached", "-q") + FROM_STDIN, gitDir = gitDir, workTree = workTree,
            input = pathspecs(deletions.map { checkNotNull(it.path.exact) }), limits = COMMIT_LIMITS))
        if (others.isNotEmpty()) runner.run(GitInvocation("add", FROM_STDIN, gitDir = gitDir, workTree = workTree,
            input = pathspecs(others.map { checkNotNull(it.path.exact) }), limits = COMMIT_LIMITS))
    }

    fun unstage(runner: GitCommandRunner, gitDir: Path, workTree: Path, entries: List<GitStatusEntry>, unborn: Boolean) {
        val paths = pathspecs(entries.flatMap { listOfNotNull(it.originalPath?.exact, it.path.exact) }.distinct())
        // `-f` only overrides rm's up-to-date check; `--cached` keeps the work tree untouched.
        if (unborn) runner.run(GitInvocation("rm", listOf("--cached", "-f", "-q") + FROM_STDIN, gitDir = gitDir, workTree = workTree,
            input = paths, limits = COMMIT_LIMITS))
        else runner.run(GitInvocation("reset", listOf("-q") + FROM_STDIN + "HEAD", gitDir = gitDir, workTree = workTree,
            input = paths, allowedExitCodes = setOf(0, 1), limits = COMMIT_LIMITS))
    }

    /** Git-compatible exclusive locks cover final validation, index capture and ref publication. */
    fun <T> withCommitLocks(gitDir: Path, operationId: String, block: () -> T): T {
        val acquired = mutableListOf<Path>()
        try {
            for (name in listOf("index.lock", "HEAD.lock")) {
                val file = gitDir.resolve(name)
                try { Files.createFile(file) } catch (_: FileAlreadyExistsException) {
                    refuse("WORKTREE_BUSY", "Another Git writer holds the index or HEAD lock. Read the current status before trying again.")
                }
                acquired.add(file)
                Files.writeString(file, "decomp-operation:$operationId\n")
            }
            return block()
        } finally {
            acquired.asReversed().forEach { Files.deleteIfExists(it) }
        }
    }

    /** Only a restarted operation's own lock markers may be reclaimed, never an external lock. */
    fun reclaimCommitLocks(gitDir: Path, staging: Path, operationId: String) {
        val refNameFile = staging.resolve("ref-name")
        val privateLock = staging.resolve("ref-lock")
        if (Files.isRegularFile(refNameFile, NOFOLLOW_LINKS) && Files.isRegularFile(privateLock, NOFOLLOW_LINKS)) {
            val ref = GitStorage.read(refNameFile, 4096).toString(Charsets.UTF_8)
            check(GitRefNames.isObservedRefName(ref))
            val refLock = gitDir.resolve("$ref.lock")
            // The private hard link proves inode ownership even if the process died while writing
            // the lock. Never remove a different writer's replacement at the same pathname.
            if (Files.isRegularFile(refLock, NOFOLLOW_LINKS) && Files.isSameFile(refLock, privateLock)) Files.delete(refLock)
        }
        for (name in listOf("index.lock", "HEAD.lock")) {
            val file = gitDir.resolve(name)
            if (Files.isRegularFile(file, NOFOLLOW_LINKS) && Files.size(file) < 256 &&
                Files.readString(file) == "decomp-operation:$operationId\n") Files.delete(file)
        }
    }

    /** Capture the locked index into an immutable tree and create an unpublished commit. No hooks run. */
    fun createCommit(runner: GitCommandRunner, gitDir: Path, workTree: Path, messageFile: Path,
        policy: GitRepositoryPolicy, observation: GitWorkspaceObservation): String {
        val index = messageFile.parent.resolve("reviewed-index")
        Files.copy(gitDir.resolve("index"), index)
        val tree = runner.run(GitInvocation("write-tree", gitDir = gitDir, workTree = workTree,
            variables = mapOf("GIT_INDEX_FILE" to index.toString()), limits = COMMIT_LIMITS)).text.trim()
        check(observation.objectFormat.objectIdOrNull(tree) != null)
        val identity = mapOf("GIT_AUTHOR_NAME" to policy.identityName, "GIT_AUTHOR_EMAIL" to policy.identityEmail,
            "GIT_COMMITTER_NAME" to policy.identityName, "GIT_COMMITTER_EMAIL" to policy.identityEmail)
        val parent = observation.head.objectId?.let { listOf("-p", it) } ?: emptyList()
        val commit = runner.run(GitInvocation("commit-tree", listOf("--no-gpg-sign", tree) + parent +
            listOf("-F", messageFile.toString()), gitDir = gitDir, variables = identity, limits = COMMIT_LIMITS)).text.trim()
        return checkNotNull(observation.objectFormat.objectIdOrNull(commit))
    }

    /**
     * HEAD.lock pins the symbolic target. Publish using Git's files-backend protocol: exclusively
     * create the target's .lock, compare its old value under that lock, then atomically rename.
     * update-ref cannot be used while we own HEAD.lock: it also locks HEAD for branch updates.
     * A loose ref safely supersedes a packed ref; neither packed-refs nor reflogs are rewritten.
     */
    fun publishCommit(runner: GitCommandRunner, gitDir: Path, staging: Path, head: GitHeadObservation,
        format: GitObjectFormat, commit: String, published: () -> Unit) {
        val ref = head.refName
        val target = gitDir.resolve(ref ?: "HEAD")
        val privateLock = staging.resolve("ref-lock")
        val refLock = if (ref == null) null else {
            GitStorage.directories(gitDir, *ref.split('/').dropLast(1).toTypedArray())
            Files.writeString(staging.resolve("ref-name"), ref)
            Files.createFile(privateLock)
            val file = target.resolveSibling("${target.fileName}.lock")
            // Exclusive link creation obeys Git's lock protocol and retains an ownership witness
            // in staging for restart cleanup, including death halfway through the lock write.
            try { Files.createLink(file, privateLock) } catch (_: FileAlreadyExistsException) {
                refuse("WORKTREE_BUSY", "The reviewed branch is locked by another Git writer. Nothing was published.")
            }
            file
        }
        var moved = false
        try {
            if (GitRepositoryInspector.head(runner, gitDir, format) != head) {
                refuse("REF_CHANGED", "The reviewed HEAD changed. Nothing was published; read the current state first.")
            }
            val file = refLock ?: Files.createFile(staging.resolve("new-head"))
            FileChannel.open(file, WRITE, NOFOLLOW_LINKS).use { channel ->
                val bytes = ByteBuffer.wrap("$commit\n".toByteArray(Charsets.US_ASCII))
                while (bytes.hasRemaining()) channel.write(bytes)
                channel.force(true)
            }
            Files.move(file, target, ATOMIC_MOVE)
            moved = true
            published() // Preserve the known object even if directory forcing or cleanup fails.
            GitStorage.forceDirectory(target.parent)
        } finally {
            if (!moved && refLock != null && Files.isRegularFile(refLock, NOFOLLOW_LINKS) &&
                Files.isSameFile(refLock, privateLock)) Files.delete(refLock)
        }
    }

    data class SnapshotCapture(val commitments: Map<String, GitSourceCommitment>, val blobs: Map<String, String>)

    /** Both hashes and size come from the same bounded read, never from separate snapshot passes. */
    fun captureSnapshot(snapshot: Path, format: GitObjectFormat): SnapshotCapture? {
        if (!Files.isDirectory(snapshot, NOFOLLOW_LINKS)) return null
        val commitments = sortedMapOf<String, GitSourceCommitment>()
        val blobs = sortedMapOf<String, String>()
        var bytes = 0L
        var valid = true
        Files.walkFileTree(snapshot, emptySet(), 65, object : SimpleFileVisitor<Path>() {
            override fun preVisitDirectory(directory: Path, attributes: BasicFileAttributes): FileVisitResult {
                val relative = snapshot.relativize(directory)
                if (directory != snapshot && relative.nameCount == 1 && relative.toString() in GitTrackingPolicy.UNCOPIED_ROOTS)
                    return FileVisitResult.SKIP_SUBTREE
                if (directory != snapshot && directory.fileName.toString() == ".git") { valid = false; return FileVisitResult.TERMINATE }
                return FileVisitResult.CONTINUE
            }
            override fun visitFile(file: Path, attributes: BasicFileAttributes): FileVisitResult {
                val relative = snapshot.relativize(file).joinToString("/")
                if (snapshot.relativize(file).nameCount == 1 && relative in GitTrackingPolicy.UNCOPIED_ROOTS) return FileVisitResult.CONTINUE
                if (!attributes.isRegularFile || file.fileName.toString() == ".git" || blobs.size >= GitSourceCopy.MAX_FILES ||
                    attributes.size() > GitSourceCopy.MAX_BYTES - bytes) { valid = false; return FileVisitResult.TERMINATE }
                val sha256 = MessageDigest.getInstance("SHA-256")
                val blob = MessageDigest.getInstance(if (format == GitObjectFormat.SHA256) "SHA-256" else "SHA-1")
                blob.update("blob ${attributes.size()}\u0000".toByteArray(Charsets.US_ASCII))
                var size = 0L
                Files.newInputStream(file, NOFOLLOW_LINKS).use { input ->
                    val buffer = ByteArray(64 * 1024)
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        size += count
                        if (size > attributes.size()) { valid = false; return FileVisitResult.TERMINATE }
                        sha256.update(buffer, 0, count); blob.update(buffer, 0, count)
                    }
                }
                if (size != attributes.size()) { valid = false; return FileVisitResult.TERMINATE }
                bytes += size
                commitments[relative] = GitSourceCommitment(sha256.digest().hex(), size)
                blobs[relative] = blob.digest().hex()
                return FileVisitResult.CONTINUE
            }
        })
        return SnapshotCapture(commitments, blobs).takeIf { valid }
    }

    /** `path -> blob ID` of a commit's tree; null when it holds anything but regular blobs. */
    fun commitBlobs(runner: GitCommandRunner, gitDir: Path, format: GitObjectFormat, commit: String): Map<String, String>? {
        val result = runner.run(GitInvocation("ls-tree", listOf("-r", "-z", "--full-tree", commit), gitDir = gitDir, truncateStdout = true,
            limits = GitExecutionLimits(Duration.ofMinutes(1), 32 * 1024 * 1024, 16 * 1024)))
        if (result.stdoutTruncated) return null
        val blobs = sortedMapOf<String, String>()
        for (record in GitReads.records(result.stdout)) {
            if (record.isEmpty()) continue
            val tab = record.indexOf('\t'.code.toByte())
            if (tab < 0) return null
            val fields = String(record, 0, tab, Charsets.US_ASCII).split(' ')
            if (fields.size != 3 || fields[1] != "blob" || fields[0] !in setOf("100644", "100755")) return null
            val path = GitPath.of(record.copyOfRange(tab + 1, record.size)).exact ?: return null
            blobs[path] = format.objectIdOrNull(fields[2]) ?: return null
        }
        return blobs
    }

    fun encodeMapping(mapping: GitMappingRecord): String = buildJsonObject {
        put("schemaVersion", 1); put("repositoryId", mapping.repositoryId); put("objectId", mapping.objectId)
        put("revisionId", mapping.revisionId); put("sourceSha256", mapping.sourceSha256)
        put("recordedAt", mapping.recordedAt.toString()); put("worktreeDirty", mapping.worktreeDirty)
    }.toString()

    fun decodeMapping(repositoryId: String, objectId: String, bytes: ByteArray): GitMappingRecord? = try {
        val value = Json.parseToJsonElement(bytes.toString(Charsets.UTF_8)).jsonObject
        fun text(name: String) = (value.getValue(name) as JsonPrimitive).also { require(it.isString) }.content
        require(value.getValue("schemaVersion").jsonPrimitive.intOrNull == 1 && text("repositoryId") == repositoryId && text("objectId") == objectId)
        GitMappingRecord(repositoryId, objectId, text("revisionId").also { require(it.matches(Regex("[A-Za-z0-9][A-Za-z0-9_-]{0,127}"))) },
            text("sourceSha256").also { require(it.matches(Regex("[0-9a-f]{64}"))) }, Instant.parse(text("recordedAt")),
            checkNotNull(value.getValue("worktreeDirty").jsonPrimitive.booleanOrNull))
    } catch (_: Exception) { null }
}
