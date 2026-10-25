package decompengine.git

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.time.Duration

/**
 * A remote, transfer or integration intent (#585-#601). [parameters] are the action's declared
 * fields and are persisted with the operation; [content] is request-only bulk data (a conflict
 * resolution's text) that is never persisted, only its digest.
 */
data class GitSyncRequest(
    override val action: GitOperationAction,
    val worktreeId: String,
    val guards: GitGuards,
    val parameters: Map<String, String?> = emptyMap(),
    val content: String? = null,
) : GitRepositoryRequest {
    init {
        require(action in ACTIONS)
        require(parameters.size <= 16 && parameters.all { (key, value) -> key.matches(Regex("[A-Za-z][A-Za-z0-9]{0,31}")) && (value == null || value.length <= 2048) })
    }

    val contentSha256: String? get() = content?.let(GitStorage::sha256) ?: parameters["contentSha256"]

    override val digest get() = GitStorage.sha256(buildString {
        append(action.wireName).append('\n').append(worktreeId).append('\n').append(guards.text).append('\n')
        parameters.filterKeys { it != "contentSha256" }.toSortedMap().forEach { (key, value) -> append(key).append('=').append(value ?: "\u0000").append('\n') }
        append(contentSha256 ?: "-").append('\n')
    })

    fun text(name: String): String = parameters[name] ?: throw GitOperationRefusal("VALIDATION_FAILED", "The $name field is required.")

    override fun toString() = "GitSyncRequest(${action.wireName}, $worktreeId)"

    companion object {
        val ACTIONS = setOf(GitOperationAction.REMOTE_ADD, GitOperationAction.REMOTE_REMOVE, GitOperationAction.FETCH,
            GitOperationAction.MERGE, GitOperationAction.MERGE_ABORT, GitOperationAction.CONFLICT_SAVE, GitOperationAction.CONFLICT_COMPLETE,
            GitOperationAction.PUSH, GitOperationAction.PUSH_RECONCILE)
        val REMOTE = setOf(GitOperationAction.REMOTE_ADD, GitOperationAction.REMOTE_REMOVE, GitOperationAction.FETCH,
            GitOperationAction.PUSH, GitOperationAction.PUSH_RECONCILE)
        /** Actions whose Git process can be cancelled while it runs. */
        val CANCELLABLE = setOf(GitOperationAction.FETCH, GitOperationAction.CLONE)
    }
}

/** Create a managed repository from an allowlisted remote (#592). */
data class GitCloneRequest(val url: String, val remoteName: String, val branch: String?) : GitRepositoryRequest {
    override val action get() = GitOperationAction.CLONE
    override val digest get() = GitStorage.sha256("git.clone\n$url\n$remoteName\n${branch ?: "\u0000"}\n")
}

/** The latest reported transfer phase; percent is Git's own estimate when it gives one. */
data class GitProgress(val phase: String, val percent: Int?) {
    init { require(phase.length in 1..64 && phase.all { it.isLetterOrDigit() || it == ' ' } && (percent == null || percent in 0..100)) }

    companion object {
        private val LINE = Regex("^(?:remote: )?([A-Za-z][A-Za-z ]{0,62}[A-Za-z]):\\s+(?:([0-9]{1,3})%)?")

        /** Known Git phases only; anything else (including remote-supplied text) is ignored. */
        private val PHASES = setOf("Enumerating objects", "Counting objects", "Compressing objects", "Receiving objects",
            "Resolving deltas", "Writing objects", "Updating files", "Checking connectivity")

        fun parse(line: String): GitProgress? {
            val match = LINE.find(line) ?: return null
            val phase = match.groupValues[1]
            if (phase !in PHASES) return null
            return GitProgress(phase, match.groupValues[2].takeIf { it.isNotEmpty() }?.toInt()?.coerceIn(0, 100))
        }
    }
}

/** Fetch, clone and remote-tracking helpers (#592, #593). */
internal object GitTransfers {
    fun limits(policy: GitRemotePolicy) = GitExecutionLimits(policy.limits.timeout, 1024 * 1024, 64 * 1024)

    /**
     * Fetch every branch of [location] into `refs/remotes/<name>/` only. No tags, no submodules,
     * no FETCH_HEAD and no work tree: fetching can never merge or check out anything.
     */
    fun fetch(runner: GitCommandRunner, gitDir: Path, location: GitRemoteLocation, name: String, policy: GitRemotePolicy,
        control: GitProcessControl, tags: Boolean = false): GitCommandResult {
        val refspecs = buildList {
            add("+refs/heads/*:refs/remotes/$name/*")
            if (tags) add("refs/tags/*:refs/tags/*")
        }
        return runner.run(GitInvocation("fetch", listOf("--no-tags", "--no-recurse-submodules", "--no-write-fetch-head",
            "--no-auto-maintenance", "--no-write-commit-graph", "--prune", "--progress", "--", location.url) + refspecs,
            gitDir = gitDir, limits = limits(policy), transport = GitTransports.context(location, policy), control = control))
    }

    /** The branch the remote's HEAD names, or null when it has none. */
    fun remoteHead(runner: GitCommandRunner, location: GitRemoteLocation, policy: GitRemotePolicy, control: GitProcessControl): String? {
        val result = runner.run(GitInvocation("ls-remote", listOf("--symref", "--", location.url, "HEAD"),
            limits = GitExecutionLimits(Duration.ofSeconds(60), 64 * 1024, 64 * 1024), transport = GitTransports.context(location, policy),
            control = control))
        return result.text.lineSequence().firstNotNullOfOrNull { line ->
            Regex("^ref: refs/heads/([^\t]+)\tHEAD$").matchEntire(line)?.groupValues?.get(1)
        }
    }

    /** Partial pack files a stopped transfer can leave behind; refs are only updated after a complete pack. */
    fun removePartialPacks(gitDir: Path) {
        val packs = gitDir.resolve("objects").resolve("pack")
        if (!Files.isDirectory(packs, NOFOLLOW_LINKS)) return
        Files.newDirectoryStream(packs).use { entries ->
            entries.filter { it.fileName.toString().startsWith("tmp_") }.forEach { Files.deleteIfExists(it) }
        }
        val incoming = gitDir.resolve("objects")
        Files.newDirectoryStream(incoming).use { entries ->
            entries.filter { it.fileName.toString().startsWith("incoming-") || it.fileName.toString().startsWith("tmp_objdir") }
                .forEach { GitStorage.deleteTree(it) }
        }
    }

    /** Remote-tracking refs of one remote, for display and divergence. */
    fun trackingRefs(runner: GitCommandRunner, gitDir: Path, format: GitObjectFormat, name: String): List<GitRefEntry> {
        val result = runner.run(GitInvocation("for-each-ref", listOf("--format=%(objectname)%00%(refname)", "--count=201", "refs/remotes/$name/"),
            gitDir = gitDir))
        return result.text.lineSequence().filter { it.isNotEmpty() }.mapNotNull { line ->
            val parts = line.split('\u0000')
            if (parts.size != 2 || !GitRefNames.isObservedRefName(parts[1])) null
            else format.objectIdOrNull(parts[0])?.let { GitRefEntry(parts[1], it, null) }
        }.take(200).toList()
    }
}
