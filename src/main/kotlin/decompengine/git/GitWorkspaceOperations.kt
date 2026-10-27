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
    fun select(record: GitRepositoryRecord, observation: GitWorkspaceObservation, fileIds: List<String>, stage: Boolean,
        worktreeId: String = record.worktreeId): List<GitStatusEntry> {
        if (!observation.status.complete) refuse("STATUS_INCOMPLETE", "The status is too large to review completely; selection is unavailable.")
        // One path can have two records: a staged deletion and an untracked replacement share a
        // file identity. Resolve each selection against the record the action applies to.
        val byId = observation.status.entries.groupBy { it.path.fileId(worktreeId) }
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
        }.also { selected -> refuseOverlap(observation, selected, stage) }
    }

    /**
     * Pathspecs match descendants, and both add and reset resolve index file/directory conflicts
     * by removing ancestors. Neither direction may silently act on an unselected index entry.
     */
    private fun refuseOverlap(observation: GitWorkspaceObservation, selected: List<GitStatusEntry>, stage: Boolean) {
        val chosen = selected.toSet()
        // Reset also restores rename sources, so protect ancestors of every expanded path.
        val paths = selected.flatMap { listOfNotNull(it.path.exact, it.originalPath?.exact.takeUnless { stage }) }
        val prefixes = selected.flatMap { listOfNotNull(it.path.exact, it.originalPath?.exact) }.map { "$it/" }
        val overlapping = observation.status.entries.any { entry ->
            val purelyUntracked = entry.untracked && entry.staged == GitIndexChange.NONE && entry.unstaged == GitIndexChange.NONE
            if (entry in chosen || entry.ignored || purelyUntracked) false
            else {
                val descendant = listOfNotNull(entry.path.exact, entry.originalPath?.exact).any { path ->
                    prefixes.any { path.startsWith(it) }
                }
                // A staged deletion has no remaining index entry. Reset must also protect
                // unselected staged ancestors that it would remove while restoring a child.
                val ancestor = (stage || entry.staged != GitIndexChange.NONE) &&
                    entry.staged != GitIndexChange.DELETED && entry.path.exact?.let { path ->
                    paths.any { it.startsWith("$path/") }
                } == true
                descendant || ancestor
            }
        }
        if (overlapping) refuse("SELECTION_OVERLAP", "A selected path overlaps other tracked changes. Select those entries explicitly or resolve the overlap first.")
    }

    /** The reviewed selection must be exactly today's staged set: nothing swept in, nothing left out. */
    fun requireStagedSet(record: GitRepositoryRecord, observation: GitWorkspaceObservation, fileIds: List<String>,
        worktreeId: String = record.worktreeId) {
        // A truncated status can hide staged files beyond its bound; never commit an unreviewable index.
        if (!observation.status.complete) refuse("STATUS_INCOMPLETE", "The status is too large to review completely; the staged set cannot be confirmed.")
        if (observation.status.entries.any { it.conflict != null }) refuse("CONFLICTED", "Resolve conflicted files before committing.")
        val staged = observation.status.entries.filter { it.staged != GitIndexChange.NONE }.map { it.path.fileId(worktreeId) }.toSet()
        if (staged.isEmpty()) refuse("NOTHING_TO_COMMIT", "No changes are staged.")
        if (staged != fileIds.toSet()) refuse("INDEX_CHANGED", "The staged files differ from the reviewed selection. Review the staged diff again.")
    }

    /**
     * Status deliberately suppresses submodules, so its staged set alone cannot authorize a
     * commit. Inspect the complete index comparison (including removed gitlinks) and refuse
     * unsupported submodule changes, even when the ordinary selected files still match.
     */
    fun requireNoStagedGitlinks(runner: GitCommandRunner, gitDir: Path, workTree: Path, headObjectId: String?, index: Path? = null) {
        val result = runner.run(GitInvocation("diff", listOf("--cached", "--raw", "-z", "--no-abbrev", "--no-renames",
            "--no-ext-diff", "--no-textconv", "--ignore-submodules=none") + listOfNotNull(headObjectId) + "--",
            gitDir = gitDir, workTree = workTree, variables = index?.let { mapOf("GIT_INDEX_FILE" to it.toString()) } ?: emptyMap(),
            truncateStdout = true, limits = COMMIT_LIMITS.copy(maxStdoutBytes = GitReads.MAX_STATUS_BYTES)))
        if (result.stdoutTruncated) refuse("STATUS_INCOMPLETE", "The staged index comparison is too large to review completely.")
        // With rename detection disabled, each NUL-delimited header has exactly one path record.
        val records = GitReads.records(result.stdout)
        if (records.size % 2 != 0) throw GitRepositoryException("REPOSITORY_CORRUPT", "Git index comparison output is malformed.")
        for (position in records.indices step 2) {
            val fields = records[position].toString(Charsets.US_ASCII).split(' ')
            if (fields.size != 5 || !fields[0].startsWith(':')) {
                throw GitRepositoryException("REPOSITORY_CORRUPT", "Git index comparison output is malformed.")
            }
            if (fields[0] == ":160000" || fields[1] == "160000") {
                refuse("EXCLUDED_PATH", "Staged submodule changes cannot be committed by the workbench. Remove them from the index before committing source files.")
            }
        }
    }

    fun validateMessage(message: String) {
        if (message.isBlank() || message.length > MAX_MESSAGE || message.any { it.isISOControl() && it != '\n' && it != '\t' }) {
            refuse("VALIDATION_FAILED", "A commit message must be 1-8192 characters of text without control characters other than newlines and tabs.")
        }
    }

    /** Paths go through NUL-separated standard input, so no selection size meets the argv bound. */
    private fun pathspecs(paths: List<String>): ByteArray = paths.joinToString("") { "$it\u0000" }.toByteArray(Charsets.UTF_8)
    private val FROM_STDIN = listOf("--pathspec-from-file=-", "--pathspec-file-nul")

    /** Capture selected bytes once, verify their reviewed commitments, then index only that capture. */
    fun stage(runner: GitCommandRunner, gitDir: Path, workTree: Path, entries: List<GitStatusEntry>,
        observation: GitWorkspaceObservation, staging: Path, index: Path, captured: () -> Unit = {}) {
        val budget = GitWorkspaceContent.Budget()
        val updates = entries.mapIndexed { position, entry ->
            val path = checkNotNull(entry.path.exact)
            if (entry.unstaged == GitIndexChange.DELETED) {
                "0 ${"0".repeat(if (observation.objectFormat == GitObjectFormat.SHA256) 64 else 40)}\t$path\u0000"
            } else {
                val file = staging.resolve("blob-$position")
                val fingerprint = GitWorkspaceContent.fingerprint(workTree, workTree.resolve(path), budget, file)
                if (fingerprint != observation.contentFingerprints[entry.path]) {
                    refuse("WORKTREE_CHANGED", "Selected content changed during capture. Read the current status before staging.")
                }
                val mode = fingerprint.substringBefore(':')
                if (mode !in setOf("100644", "100755", "120000")) {
                    refuse("SELECTION_CHANGED", "A selected path is no longer a file or link. Read the current status before staging.")
                }
                val blob = runner.run(GitInvocation("hash-object", listOf("-w", "--no-filters", "--", file.toString()),
                    gitDir = gitDir, limits = COMMIT_LIMITS)).text.trim()
                check(observation.objectFormat.objectIdOrNull(blob) != null)
                "$mode $blob\t$path\u0000"
            }
        }
        captured()
        // Index-info names exact entries (not recursive pathspecs). Deletions precede additions
        // so explicitly selected file/directory replacements work in either request order.
        val ordered = updates.filter { it.startsWith("0 ") } + updates.filterNot { it.startsWith("0 ") }
        runner.run(GitInvocation("update-index", listOf("-z", "--index-info"), gitDir = gitDir, workTree = workTree,
            variables = mapOf("GIT_INDEX_FILE" to index.toString()), input = ordered.joinToString("").toByteArray(Charsets.UTF_8),
            limits = COMMIT_LIMITS))
    }

    /** Mutate a private index against the guarded parent object, never a later resolution of HEAD. */
    fun unstage(runner: GitCommandRunner, gitDir: Path, workTree: Path, entries: List<GitStatusEntry>, parent: String?, index: Path) {
        val paths = pathspecs(entries.flatMap { listOfNotNull(it.originalPath?.exact, it.path.exact) }.distinct())
        val variables = mapOf("GIT_INDEX_FILE" to index.toString())
        if (parent == null) runner.run(GitInvocation("rm", listOf("--cached", "-f", "-q") + FROM_STDIN, gitDir = gitDir, workTree = workTree,
            variables = variables, input = paths, limits = COMMIT_LIMITS))
        else runner.run(GitInvocation("reset", listOf("-q") + FROM_STDIN + parent, gitDir = gitDir, workTree = workTree,
            variables = variables, input = paths, allowedExitCodes = setOf(0, 1), limits = COMMIT_LIMITS))
    }

    /** Publish the fully prepared index atomically while the caller owns Git's index.lock. */
    fun publishIndex(gitDir: Path, index: Path) {
        FileChannel.open(index, WRITE, NOFOLLOW_LINKS).use { it.force(true) }
        Files.move(index, gitDir.resolve("index"), ATOMIC_MOVE, java.nio.file.StandardCopyOption.REPLACE_EXISTING)
        GitStorage.forceDirectory(gitDir)
    }

    /** Git-compatible exclusive locks cover final validation, index capture and ref publication. */
    fun <T> withCommitLocks(gitDir: Path, staging: Path, operationId: String, block: () -> T): T {
        val acquired = mutableListOf<Pair<Path, Path>>()
        try {
            for (name in listOf("index.lock", "HEAD.lock")) {
                val file = gitDir.resolve(name)
                val witness = staging.resolve(name)
                Files.createFile(witness)
                FileChannel.open(witness, WRITE, NOFOLLOW_LINKS).use { channel ->
                    val bytes = ByteBuffer.wrap("decomp-operation:$operationId\n".toByteArray(Charsets.US_ASCII))
                    while (bytes.hasRemaining()) channel.write(bytes)
                    channel.force(true)
                }
                // Persist the private inode witness before making the lock visible. Recovery
                // must not depend on lock contents being fully written at process death.
                GitStorage.forceDirectory(staging)
                acquired.add(file to witness)
                try { Files.createLink(file, witness) } catch (_: FileAlreadyExistsException) {
                    refuse("WORKTREE_BUSY", "Another Git writer holds the index or HEAD lock. Read the current status before trying again.")
                }
                GitStorage.forceDirectory(gitDir)
            }
            return block()
        } finally {
            acquired.asReversed().forEach { (file, witness) ->
                if (Files.isRegularFile(file, NOFOLLOW_LINKS) && Files.isSameFile(file, witness)) Files.delete(file)
            }
        }
    }

    /** Also pin the symbolic HEAD's branch while a stage/unstage transaction publishes its index. */
    fun <T> withWorkspaceLocks(runner: GitCommandRunner, gitDir: Path, staging: Path, operationId: String,
        format: GitObjectFormat, commonDir: Path = gitDir, block: () -> T): T = withCommitLocks(gitDir, staging, operationId) {
        val ref = GitRepositoryInspector.head(runner, gitDir, format).refName
        if (ref == null) block() else {
            // Linked HEAD/index are private, but their symbolic branch belongs to the common directory.
            GitStorage.directories(commonDir, *ref.split('/').dropLast(1).toTypedArray())
            Files.writeString(staging.resolve("ref-name"), ref)
            val witness = Files.createFile(staging.resolve("ref-lock"))
            GitStorage.forceDirectory(staging)
            val file = commonDir.resolve("$ref.lock")
            try { Files.createLink(file, witness) } catch (_: FileAlreadyExistsException) {
                refuse("WORKTREE_BUSY", "Another Git writer holds the reviewed branch lock. Nothing was staged.")
            }
            try {
                GitStorage.forceDirectory(file.parent)
                block()
            } finally {
                if (Files.isRegularFile(file, NOFOLLOW_LINKS) && Files.isSameFile(file, witness)) Files.delete(file)
            }
        }
    }

    /** Reclaim proven owned inodes, never a different writer's replacement at the same name. */
    fun reclaimCommitLocks(gitDir: Path, staging: Path, operationId: String, commonDir: Path = gitDir) {
        val refNameFile = staging.resolve("ref-name")
        val privateLock = staging.resolve("ref-lock")
        if (Files.isRegularFile(refNameFile, NOFOLLOW_LINKS) && Files.isRegularFile(privateLock, NOFOLLOW_LINKS)) {
            val ref = GitStorage.read(refNameFile, 4096).toString(Charsets.UTF_8)
            check(GitRefNames.isObservedRefName(ref))
            val refLock = commonDir.resolve("$ref.lock")
            // The private hard link proves inode ownership even if the process died while writing
            // the lock. Never remove a different writer's replacement at the same pathname.
            if (Files.isRegularFile(refLock, NOFOLLOW_LINKS) && Files.isSameFile(refLock, privateLock)) Files.delete(refLock)
        }
        for (name in listOf("index.lock", "HEAD.lock")) {
            val file = gitDir.resolve(name)
            if (!Files.isRegularFile(file, NOFOLLOW_LINKS)) continue
            val witness = staging.resolve(name)
            if (Files.isRegularFile(witness, NOFOLLOW_LINKS)) {
                if (Files.isSameFile(file, witness)) Files.delete(file)
            } else if (Files.size(file) < 256 && Files.readString(file) == "decomp-operation:$operationId\n") {
                // Compatibility with complete markers left by versions predating inode witnesses.
                Files.delete(file)
            }
        }
    }

    /** Capture the locked index into an immutable tree and create an unpublished commit. No hooks run. */
    fun createCommit(runner: GitCommandRunner, gitDir: Path, workTree: Path, messageFile: Path,
        policy: GitRepositoryPolicy, observation: GitWorkspaceObservation): String {
        val index = messageFile.parent.resolve("reviewed-index")
        Files.copy(gitDir.resolve("index"), index)
        // Validate the actual captured index as well, never a later read of the live index.
        requireNoStagedGitlinks(runner, gitDir, workTree, observation.head.objectId, index)
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
        format: GitObjectFormat, commit: String, commonDir: Path = gitDir, published: () -> Unit) {
        val ref = head.refName
        // Linked HEAD/index live in their administrative directory, but attached refs belong
        // to the common repository. A private refs/ shadow would report a commit never published.
        val target = if (ref == null) gitDir.resolve("HEAD") else commonDir.resolve(ref)
        val privateLock = staging.resolve("ref-lock")
        val refLock = if (ref == null) null else {
            GitStorage.directories(commonDir, *ref.split('/').dropLast(1).toTypedArray())
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
