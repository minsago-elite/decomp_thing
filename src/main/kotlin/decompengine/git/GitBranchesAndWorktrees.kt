package decompengine.git

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.nio.file.Path
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.FileAlreadyExistsException
import java.time.Duration
import java.time.Instant

/**
 * Branch, tag and work-tree intents (#578, #579, #581). Every field is persisted with the
 * operation so restart reconciliation can compare the durable intent with actual refs.
 */
data class GitRefRequest(
    override val action: GitOperationAction,
    val worktreeId: String,
    val guards: GitGuards,
    /** New branch or tag name (create, tag, optional branch for a new work tree). */
    val name: String? = null,
    /** Registered ref selected by a switch or delete. */
    val refId: String? = null,
    /** Start, target or expected object, by action. */
    val objectId: String? = null,
    /** Owning workflow attempt of a new work tree. */
    val runId: String? = null,
) : GitRepositoryRequest {
    init { require(action in ACTIONS) }
    override val digest get() = GitStorage.sha256("${action.wireName}\n$worktreeId\n${guards.text}\n${name ?: "-"}\n" +
        "${refId ?: "-"}\n${objectId ?: "-"}\n${runId ?: "-"}\n")

    companion object {
        val ACTIONS = setOf(GitOperationAction.BRANCH_CREATE, GitOperationAction.SWITCH, GitOperationAction.BRANCH_DELETE,
            GitOperationAction.TAG, GitOperationAction.WORKTREE_ADD, GitOperationAction.WORKTREE_REMOVE)
    }
}

/** A linked work tree's registration; the primary work tree is described by its repository record. */
data class GitWorktreeRecord(
    val worktreeId: String,
    val repositoryId: String,
    val jobId: String,
    val operationId: String,
    val ownerRunId: String?,
    val createdAt: Instant,
)

/** Workflow attempts of a job and whether each is still active; supplied by the job service. */
fun interface GitJobActivity {
    fun runs(jobId: String): Map<String, Boolean>
}

internal object GitRefOperations {
    private val LIMITS = GitExecutionLimits(Duration.ofMinutes(2), 1024 * 1024, 64 * 1024)
    const val MAX_LINKED_WORKTREES = 4

    fun refuse(code: String, message: String): Nothing = GitWorkspaceMutations.refuse(code, message)

    fun requireName(runner: GitCommandRunner, name: String?, namespace: String): String {
        val value = name ?: refuse("VALIDATION_FAILED", "A name is required.")
        if (!GitRefNames.isPlausibleBranchName(value)) refuse("VALIDATION_FAILED", "The name is not a valid Git ref name.")
        val result = runner.run(GitInvocation("check-ref-format", listOf("refs/$namespace/$value"), allowedExitCodes = setOf(0, 1)))
        if (result.exitCode != 0) refuse("VALIDATION_FAILED", "The name is not a valid Git ref name.")
        return value
    }

    fun requireCommit(runner: GitCommandRunner, gitDir: Path, format: GitObjectFormat, objectId: String?): String {
        val id = objectId?.let(format::objectIdOrNull) ?: refuse("VALIDATION_FAILED", "A full object ID for this repository is required.")
        val exists = runner.run(GitInvocation("cat-file", listOf("-e", "$id^{commit}"), gitDir = gitDir, allowedExitCodes = setOf(0, 1, 128)))
        if (exists.exitCode != 0) refuse("NOT_FOUND", "The commit is not in this repository.")
        return id
    }

    fun refObject(runner: GitCommandRunner, gitDir: Path, format: GitObjectFormat, ref: String): String? {
        val result = runner.run(GitInvocation("rev-parse", listOf("-q", "--verify", ref), gitDir = gitDir, allowedExitCodes = setOf(0, 1)))
        return if (result.exitCode == 0) format.objectIdOrNull(result.text.trim()) else null
    }

    /** Create a ref only if it is absent: `update-ref <ref> <new> ""` refuses to overwrite. */
    fun createRef(runner: GitCommandRunner, gitDir: Path, ref: String, objectId: String, existsCode: String) {
        val result = runner.run(GitInvocation("update-ref", listOf("--no-deref", ref, objectId, ""), gitDir = gitDir, allowedExitCodes = setOf(0, 1, 128)))
        if (result.exitCode != 0) refuse(existsCode, "That name already exists; nothing was overwritten.")
    }

    fun deleteRef(runner: GitCommandRunner, gitDir: Path, ref: String, expected: String) {
        val result = runner.run(GitInvocation("update-ref", listOf("--no-deref", "-d", ref, expected), gitDir = gitDir, allowedExitCodes = setOf(0, 1, 128)))
        if (result.exitCode != 0) refuse("REF_CHANGED", "The branch moved since it was reviewed; nothing was deleted.")
    }

    /** Commits reachable from [objectId] but from no other branch, tag or work-tree HEAD. */
    fun unmergedCount(runner: GitCommandRunner, commonDir: Path, objectId: String, excludeRef: String?): Long {
        // `--exclude` patterns for `--branches` are written without their `refs/heads/` prefix.
        val arguments = listOf("--count", objectId, "--not") + listOfNotNull(excludeRef?.let { "--exclude=${it.removePrefix("refs/heads/")}" }) +
            listOf("--branches", "--tags")
        return runner.run(GitInvocation("rev-list", arguments, gitDir = commonDir, limits = LIMITS)).text.trim().toLongOrNull() ?: Long.MAX_VALUE
    }

    /**
     * Pin a branch through final validation AND checkout using Git's files-ref lock protocol.
     * A private inode witness lets restart recovery reclaim only our lock, never another writer's.
     * Symbolic branches are refused: locking an alias would not pin its referent.
     */
    fun lockSwitchBranch(runner: GitCommandRunner, commonDir: Path, ref: String, staging: Path): AutoCloseable {
        check(ref.startsWith("refs/heads/") && GitRefNames.isObservedRefName(ref))
        GitStorage.directories(commonDir, *ref.split('/').dropLast(1).toTypedArray())
        val witness = Files.createFile(staging.resolve("ref-lock"))
        GitStorage.replaceAtomically(staging.resolve("ref-name"), ref.toByteArray(Charsets.UTF_8))
        val file = commonDir.resolve("$ref.lock")
        try { Files.createLink(file, witness) } catch (_: FileAlreadyExistsException) {
            refuse("WORKTREE_BUSY", "Another Git writer holds the destination branch lock. Nothing was checked out.")
        }
        val ownership = AutoCloseable {
            if (Files.isRegularFile(file, NOFOLLOW_LINKS) && Files.isSameFile(file, witness)) Files.delete(file)
        }
        try {
            GitStorage.forceDirectory(file.parent)
            val symbolic = runner.run(GitInvocation("symbolic-ref", listOf("-q", ref), gitDir = commonDir, allowedExitCodes = setOf(0, 1)))
            if (symbolic.exitCode == 0) refuse("SWITCH_REFUSED", "A symbolic branch cannot be pinned for checkout. Select a direct branch or an exact commit.")
            return ownership
        } catch (failure: Throwable) { ownership.close(); throw failure }
    }

    /** Switch without guessing, recursing into submodules or running hooks. Caller pins a named branch. */
    fun switch(runner: GitCommandRunner, gitDir: Path, workTree: Path, branch: String?, objectId: String?) {
        // Ignored local files (experiment outputs) are never overwritten by a tracked destination file.
        val arguments = if (branch != null) listOf("--no-guess", "--no-recurse-submodules", "--no-overwrite-ignore", branch)
            else listOf("--no-recurse-submodules", "--no-overwrite-ignore", "--detach", checkNotNull(objectId))
        val result = runner.run(GitInvocation("switch", listOf("-q") + arguments, gitDir = gitDir, workTree = workTree,
            allowedExitCodes = setOf(0, 1, 128), limits = LIMITS))
        if (result.exitCode != 0) refuse("SWITCH_REFUSED", "Git refused the switch, for example because a file would be overwritten or the branch is checked out elsewhere. Nothing was discarded.")
    }

    /** Index paths recorded as gitlinks (mode 160000); null for a name that is not valid UTF-8. */
    fun gitlinkPaths(runner: GitCommandRunner, gitDir: Path, workTree: Path): List<String?> {
        val result = runner.run(GitInvocation("ls-files", listOf("--stage", "-z"), gitDir = gitDir, workTree = workTree, limits = LIMITS))
        return result.stdout.toString(Charsets.ISO_8859_1).split('\u0000').filter { it.startsWith("160000 ") }.map { record ->
            GitPath.of(record.substringAfter('\t').toByteArray(Charsets.ISO_8859_1)).exact
        }
    }

    fun addWorktree(runner: GitCommandRunner, commonDir: Path, path: Path, objectId: String, branch: String?) {
        val arguments = listOf("add", "-q") + (if (branch != null) listOf("-b", branch) else listOf("--detach")) + listOf(path.toString(), objectId)
        runner.run(GitInvocation("worktree", arguments, gitDir = commonDir, limits = LIMITS))
    }

    /** Without force: Git itself refuses a work tree with modifications or untracked files. */
    fun removeWorktree(runner: GitCommandRunner, commonDir: Path, path: Path, force: Boolean = false) {
        val result = runner.run(GitInvocation("worktree", listOf("remove") + listOfNotNull("--force".takeIf { force }) + path.toString(),
            gitDir = commonDir, allowedExitCodes = setOf(0, 1, 128), limits = LIMITS))
        if (result.exitCode != 0) refuse("WORKTREE_DIRTY", "Git refused to remove the work tree because it holds changes. Nothing was discarded.")
        runner.run(GitInvocation("worktree", listOf("prune"), gitDir = commonDir, limits = LIMITS))
    }

    fun encodeWorktree(record: GitWorktreeRecord): String = buildJsonObject {
        put("schemaVersion", 1); put("worktreeId", record.worktreeId); put("repositoryId", record.repositoryId)
        put("jobId", record.jobId); put("operationId", record.operationId)
        put("ownerRunId", record.ownerRunId?.let(::JsonPrimitive) ?: JsonNull); put("createdAt", record.createdAt.toString())
    }.toString()

    fun decodeWorktree(repositoryId: String, worktreeId: String, bytes: ByteArray): GitWorktreeRecord? = try {
        val value = Json.parseToJsonElement(bytes.toString(Charsets.UTF_8)).jsonObject
        fun text(name: String) = (value.getValue(name) as JsonPrimitive).also { require(it.isString) }.content
        require(value.getValue("schemaVersion").jsonPrimitive.intOrNull == 1 && text("worktreeId") == worktreeId && text("repositoryId") == repositoryId)
        GitWorktreeRecord(worktreeId, repositoryId, text("jobId"), text("operationId"),
            value.getValue("ownerRunId").let { if (it == JsonNull) null else (it as JsonPrimitive).content },
            Instant.parse(text("createdAt")))
    } catch (_: Exception) { null }
}
