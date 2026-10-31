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
    /** Server-retained destination branch for merge admission and crash recovery; never client authority. */
    val retainedDestinationRef: String? = null,
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
        val result = runner.run(GitInvocation("fetch", listOf("--no-tags", "--no-recurse-submodules", "--no-write-fetch-head",
            "--no-auto-maintenance", "--no-write-commit-graph", "--prune", "--progress", "--", location.url) + refspecs,
            gitDir = gitDir, limits = limits(policy), transport = GitTransports.context(location, policy), control = control))
        // gitDir is operation-owned staging/quarantine. Reject unsupported name bytes there,
        // including clone tags, before any objects or refs can be promoted into live storage.
        val refs = runner.run(GitInvocation("for-each-ref", listOf("--format=%(refname)", "refs/remotes/$name/") +
            (if (tags) listOf("refs/tags/") else emptyList()), gitDir = gitDir, truncateStdout = true,
            limits = GitExecutionLimits(Duration.ofSeconds(60), 8 * 1024 * 1024, 64 * 1024)))
        if (refs.stdoutTruncated) throw GitRepositoryException("REPOSITORY_UNSUPPORTED", "The remote has more refs than the workbench can enumerate.")
        refText(refs)
        return result
    }

    /**
     * Receive objects and refs in operation-owned storage. The sole alternate is the managed
     * object store (read-only); neither a stopped process nor a rejected final pack can grow it.
     * Only after admission do immutable objects move into the live store and CAS ref transactions
     * publish the tracking changes. Files-backend namespace transitions first prune obsolete
     * conflicting refs; a stopped publication can be completed by an explicit fetch retry.
     * Restart reconciliation removes the quarantine.
     */
    fun fetchQuarantined(runner: GitCommandRunner, live: Path, quarantine: Path, format: GitObjectFormat,
        location: GitRemoteLocation, name: String, policy: GitRemotePolicy, remainingBytes: Long, control: GitProcessControl,
        afterNamespacePrune: () -> Unit = {}): Int {
        val before = allTrackingRefs(runner, live, format, name).associate { it.name to it.objectId }
        runner.run(GitInvocation("init", listOf("--quiet", "--bare", "--object-format=${format.wireName}", quarantine.toString())))
        Files.writeString(quarantine.resolve("objects/info/alternates"), live.resolve("objects").toString() + "\n")
        for ((ref, objectId) in before) {
            val path = quarantine.resolve(ref)
            GitStorage.directories(quarantine, *quarantine.relativize(path.parent).map { it.toString() }.toTypedArray())
            Files.writeString(path, "$objectId\n")
        }
        fetch(runner, quarantine, location, name, policy, control)
        val after = allTrackingRefs(runner, quarantine, format, name).associate { it.name to it.objectId }
        // Include quarantine metadata and all final object files, even on a very fast transfer.
        if (GitDiskWatch(quarantine, remainingBytes) { false }.exceeded()) {
            throw GitOperationRefusal("TRANSFER_LIMIT", "The fetch exceeded the repository size bound. Its quarantined objects and refs were not accepted.")
        }
        control.stop()?.let { reason -> throw GitCommandException(GitCommandException.Kind.STOPPED, "The fetch was stopped.", stopReason = reason) }
        val changed = (before.keys + after.keys).filter { before[it] != after[it] }
        // Git's files backend cannot prepare a create of a/b while a exists (or vice versa),
        // even if the same transaction deletes a. Prune only obsolete namespace blockers first.
        // Both phases use CAS; no surviving ref, local branch or checkout is removed. A crash
        // between phases leaves a safely pruned tracking namespace that the next fetch refreshes.
        val creates = java.util.TreeSet(after.keys - before.keys)
        val blockers = before.keys.filter { ref ->
            ref !in after && (creates.ceiling("$ref/")?.startsWith("$ref/") == true ||
                generateSequence(ref.substringBeforeLast('/', "")) { it.substringBeforeLast('/', "") }
                    .takeWhile { it.isNotEmpty() }.any { it in creates })
        }.toSet()
        val prune = refTransaction(before.filterKeys { it in blockers }, emptyMap())
        val transaction = refTransaction(before - blockers, after)
        val promoted = mutableListOf<Path>()
        var publishingRefs = false
        try {
            val objects = quarantine.resolve("objects")
            Files.walk(objects).use { paths ->
                for (file in paths.filter { Files.isRegularFile(it, NOFOLLOW_LINKS) }.toList()) {
                    val relative = objects.relativize(file)
                    if (relative.getName(0).toString() == "info") continue // Never publish the alternate.
                    val target = live.resolve("objects").resolve(relative)
                    GitStorage.directories(live.resolve("objects"), *relative.parent.map { it.toString() }.toTypedArray())
                    if (!Files.exists(target, NOFOLLOW_LINKS)) {
                        Files.move(file, target) // No replacement of a pre-existing/local object.
                        promoted.add(target)
                    }
                }
            }
            publishingRefs = true
            if (blockers.isNotEmpty()) {
                runner.run(GitInvocation("update-ref", listOf("--stdin"), gitDir = live, input = prune))
                afterNamespacePrune()
            }
            runner.run(GitInvocation("update-ref", listOf("--stdin"), gitDir = live, input = transaction))
        } catch (failure: Exception) {
            // Never remove objects after an uncertain ref publication. They were already admitted
            // within the cap; reconciliation may observe committed refs even if output was lost.
            if (!publishingRefs) promoted.forEach { Files.deleteIfExists(it) }
            throw failure
        }
        return changed.size
    }

    private fun refTransaction(before: Map<String, String>, after: Map<String, String>): ByteArray {
        val transaction = buildString {
            append("start\n")
            for (ref in before.keys + after.keys) {
                val old = before[ref]
                val next = after[ref]
                if (old == next) continue
                when {
                    next == null -> append("delete $ref $old\n")
                    old == null -> append("create $ref $next\n")
                    else -> append("update $ref $next $old\n")
                }
            }
            append("prepare\ncommit\n")
        }.toByteArray()
        if (transaction.size > 4 * 1024 * 1024) throw GitOperationRefusal("TRANSFER_LIMIT", "The fetch changed more refs than one bounded transaction can publish.")
        return transaction
    }

    data class Advertisement(val branch: String?, val format: GitObjectFormat, val headObjectId: String?)

    /** Discover the remote's format before init, including empty SHA-256 repositories. */
    fun advertisement(runner: GitCommandRunner, location: GitRemoteLocation, policy: GitRemotePolicy, control: GitProcessControl): Advertisement {
        val capability = java.util.concurrent.atomic.AtomicReference<String?>()
        val formatLine = Regex("ls-remote< object-format=([a-z0-9]+)\\s*$")
        val result = runner.run(GitInvocation("ls-remote", listOf("--symref", "--", location.url, "HEAD"),
            limits = GitExecutionLimits(Duration.ofSeconds(60), 64 * 1024, 64 * 1024),
            transport = GitTransports.context(location, policy, discoverFormat = true),
            control = GitProcessControl(stop = control.stop, progress = { line ->
                // Capture the capability before a large advertisement displaces the bounded tail.
                // This listener is private: no packet diagnostics become operation progress.
                formatLine.find(line)?.groupValues?.get(1)?.let { capability.compareAndSet(null, it) }
            })))
        val text = refText(result)
        val branch = text.lineSequence().firstNotNullOfOrNull { line ->
            Regex("^ref: refs/heads/([^\t]+)\tHEAD$").matchEntire(line)?.groupValues?.get(1)
        }
        // SHA-1 is the protocol default when an older server lacks object-format. A detached
        // SHA-256 HEAD also identifies its format through its full advertised object ID.
        val headId = text.lineSequence().map { it.substringBefore('\t') }
            .firstOrNull { id -> GitObjectFormat.SHA1.objectIdOrNull(id) != null || GitObjectFormat.SHA256.objectIdOrNull(id) != null }
        val format = capability.get()?.let(GitObjectFormat::fromGit)
            ?: if (headId?.length == GitObjectFormat.SHA256.hexLength) GitObjectFormat.SHA256 else GitObjectFormat.SHA1
        if (format == GitObjectFormat.UNKNOWN) throw GitOperationRefusal("REPOSITORY_UNSUPPORTED", "The remote uses an unsupported object format.")
        return Advertisement(branch, format, headId)
    }

    /** Ref names are identities, not display text: replacement decoding can merge distinct refs. */
    private fun refText(result: GitCommandResult): String = try {
        result.stdout.decodeToString(throwOnInvalidSequence = true)
    } catch (_: java.nio.charset.CharacterCodingException) {
        throw GitRepositoryException("REPOSITORY_UNSUPPORTED", "The remote contains a non-UTF-8 ref name. No refs were published to the managed repository.")
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

    /** Every remote-tracking ref of one remote, for deletion; a listing past its bound is refused, never truncated. */
    fun allTrackingRefs(runner: GitCommandRunner, gitDir: Path, format: GitObjectFormat, name: String): List<GitRefEntry> {
        val result = runner.run(GitInvocation("for-each-ref", listOf("--format=%(objectname)%00%(refname)", "refs/remotes/$name/"),
            gitDir = gitDir, truncateStdout = true, limits = GitExecutionLimits(Duration.ofSeconds(60), 8 * 1024 * 1024, 64 * 1024)))
        if (result.stdoutTruncated) throw GitRepositoryException("REPOSITORY_UNSUPPORTED", "The remote has more tracking refs than the workbench can enumerate.")
        return refText(result).lineSequence().filter { it.isNotEmpty() }.map { line ->
            val parts = line.split('\u0000')
            GitRefEntry(parts[1], format.objectIdOrNull(parts[0]) ?: throw GitRepositoryException("REPOSITORY_CORRUPT", "A tracking ref is invalid."), null)
        }.toList()
    }

    /** Remote-tracking refs of one remote, for display and divergence. */
    fun trackingRefs(runner: GitCommandRunner, gitDir: Path, format: GitObjectFormat, name: String): List<GitRefEntry> {
        val result = runner.run(GitInvocation("for-each-ref", listOf("--format=%(objectname)%00%(refname)", "--count=201", "refs/remotes/$name/"),
            gitDir = gitDir))
        return refText(result).lineSequence().filter { it.isNotEmpty() }.mapNotNull { line ->
            val parts = line.split('\u0000')
            if (parts.size != 2 || !GitRefNames.isObservedRefName(parts[1])) null
            else format.objectIdOrNull(parts[0])?.let { GitRefEntry(parts[1], it, null) }
        }.take(200).toList()
    }
}
