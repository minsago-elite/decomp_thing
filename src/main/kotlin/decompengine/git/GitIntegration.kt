package decompengine.git

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.time.Duration
import java.time.Instant

/** The integration strategies the workbench offers (#595). History rewriting is never offered. */
enum class GitIntegrationStrategy(val wireName: String) { FAST_FORWARD("fast-forward"), MERGE("merge"), REBASE("rebase") }

/**
 * A merge started by the workbench (#596). Written before Git runs, so a restart can tell the
 * reviewed base and target apart from whatever Git left behind.
 */
data class GitIntegrationRecord(
    val operationId: String,
    val worktreeId: String,
    val strategy: GitIntegrationStrategy,
    val branch: String,
    val headBefore: String,
    val target: String,
    val trackingRef: String,
    val startedAt: Instant,
)

/** One unresolved path with its stage blobs (#597). */
data class GitConflictEntry(val path: GitPath, val baseObjectId: String?, val oursObjectId: String?, val theirsObjectId: String?,
    val modes: Set<String> = setOf("100644")) {
    // core.symlinks=false materializes a link as a plain file: filesystem type alone is not enough.
    val plainFile: Boolean get() = modes.all { it == "100644" || it == "100755" }
}

/** Divergence of a local branch from one remote-tracking ref (#595). */
data class GitDivergence(val ahead: Long, val behind: Long, val mergeBase: String?)

internal object GitIntegrations {
    const val DIRECTORY = "integrations"
    const val MAX_TEXT_BYTES = 256 * 1024
    private val LIMITS = GitExecutionLimits(Duration.ofMinutes(2), 1024 * 1024, 64 * 1024)

    fun record(directory: Path, worktreeId: String): GitIntegrationRecord? {
        val file = directory.resolve(DIRECTORY).resolve("$worktreeId.json")
        if (!Files.isRegularFile(file, NOFOLLOW_LINKS)) return null
        return try {
            val value = Json.parseToJsonElement(GitStorage.read(file, 16 * 1024).toString(Charsets.UTF_8)).jsonObject
            fun text(name: String) = value.getValue(name).jsonPrimitive.content
            GitIntegrationRecord(text("operationId"), text("worktreeId"), GitIntegrationStrategy.entries.single { it.wireName == text("strategy") },
                text("branch"), text("headBefore"), text("target"), text("trackingRef"), Instant.parse(text("startedAt")))
        } catch (_: Exception) {
            throw ManagedGitException("STORAGE_FAILED", "An integration record is unreadable. Preserve storage and inspect it.")
        }
    }

    fun write(directory: Path, record: GitIntegrationRecord) {
        val records = GitStorage.directories(directory, DIRECTORY)
        GitStorage.replaceAtomically(records.resolve("${record.worktreeId}.json"), buildJsonObject {
            put("operationId", record.operationId); put("worktreeId", record.worktreeId); put("strategy", record.strategy.wireName)
            put("branch", record.branch); put("headBefore", record.headBefore); put("target", record.target)
            put("trackingRef", record.trackingRef); put("startedAt", record.startedAt.toString())
        }.toString().toByteArray())
    }

    fun delete(directory: Path, worktreeId: String) { Files.deleteIfExists(directory.resolve(DIRECTORY).resolve("$worktreeId.json")) }

    fun mergeInProgress(gitDir: Path): Boolean = Files.exists(gitDir.resolve("MERGE_HEAD"), NOFOLLOW_LINKS)

    fun divergence(runner: GitCommandRunner, commonDir: Path, local: String, tracking: String): GitDivergence {
        val counts = runner.run(GitInvocation("rev-list", listOf("--left-right", "--count", "$local...$tracking"), gitDir = commonDir, limits = LIMITS))
            .text.trim().split(Regex("\\s+"))
        val base = runner.run(GitInvocation("merge-base", listOf(local, tracking), gitDir = commonDir, allowedExitCodes = setOf(0, 1), limits = LIMITS))
        return GitDivergence(counts[0].toLong(), counts[1].toLong(), base.text.trim().takeIf { base.exitCode == 0 && it.isNotEmpty() })
    }

    /**
     * Fast-forward or merge [target] into the checked-out branch. Hooks, signing, autostash and
     * rerere are off. Returns true when Git stopped with conflicts (MERGE_HEAD present).
     */
    fun merge(runner: GitCommandRunner, gitDir: Path, workTree: Path, target: String, strategy: GitIntegrationStrategy,
        message: String, policy: GitRepositoryPolicy): Boolean {
        val identity = mapOf("GIT_AUTHOR_NAME" to policy.identityName, "GIT_AUTHOR_EMAIL" to policy.identityEmail,
            "GIT_COMMITTER_NAME" to policy.identityName, "GIT_COMMITTER_EMAIL" to policy.identityEmail)
        val mode = if (strategy == GitIntegrationStrategy.FAST_FORWARD) listOf("--ff-only") else listOf("--no-ff", "-m", message)
        // --no-overwrite-ignore: ignored local output (experiment results, builds) is never replaced
        // by an incoming tracked file; Git refuses instead and nothing changes.
        val result = runner.run(GitInvocation("merge", listOf("-q", "--no-verify", "--no-gpg-sign", "--no-edit", "--no-stat", "--no-log",
            "--no-overwrite-ignore",
            "--no-squash", "--no-signoff", "--no-autostash", "--no-rerere-autoupdate", "--no-progress") + mode + listOf(target),
            gitDir = gitDir, workTree = workTree, variables = identity, allowedExitCodes = setOf(0, 1, 2, 128), limits = LIMITS,
            drainDiagnostics = true))
        if (result.exitCode == 0) return false
        if (mergeInProgress(gitDir)) return true
        throw GitOperationRefusal("MERGE_REFUSED", "Git refused the integration, for example because a local file would be overwritten. Nothing was changed.")
    }

    fun abort(runner: GitCommandRunner, gitDir: Path, workTree: Path) {
        val result = runner.run(GitInvocation("merge", listOf("--abort"), gitDir = gitDir, workTree = workTree, allowedExitCodes = setOf(0, 128), limits = LIMITS,
            drainDiagnostics = true))
        if (result.exitCode != 0) throw GitOperationRefusal("ABORT_REFUSED", "Git could not abort the merge. Inspect the work tree before any new request.")
    }

    /** Every unmerged path with the blob and type of each stage that exists. Parse NUL records
     * incrementally: 6,000 ordinary conflicts already exceed the normal 1 MiB capture ceiling.
     * Checkout admits at most 100,000 files per tree and a 32 MiB tree listing. Three stages over
     * the two trees' path union fit within 256 MiB; no full stdout/string copy is retained. */
    fun conflicts(runner: GitCommandRunner, gitDir: Path, workTree: Path): List<GitConflictEntry> {
        val stages = LinkedHashMap<String, MutableMap<Int, Pair<String, String>>>()
        val pending = java.io.ByteArrayOutputStream()
        fun invalid(): Nothing = GitWorkspaceMutations.refuse("REPOSITORY_UNSUPPORTED", "The conflict index exceeds its supported listing bounds.")
        fun accept() {
            val record = pending.toString(Charsets.ISO_8859_1)
            pending.reset()
            val split = record.indexOf('\t')
            if (split < 0) invalid()
            val path = record.substring(split + 1)
            val parts = record.substring(0, split).split(' ')
            if (path.isEmpty() || parts.size != 3 || parts[2] !in setOf("1", "2", "3")) invalid()
            if (path !in stages && stages.size >= 200_000) invalid()
            stages.getOrPut(path) { mutableMapOf() }[parts[2].toInt()] = parts[0] to parts[1]
        }
        runner.stream(GitInvocation("ls-files", listOf("-u", "-z"), gitDir = gitDir, workTree = workTree, limits = LIMITS),
            256L * 1024 * 1024) { chunk, count ->
            for (index in 0 until count) {
                if (chunk[index] == 0.toByte()) accept()
                else {
                    if (pending.size() >= 64 * 1024) invalid()
                    pending.write(chunk[index].toInt())
                }
            }
        }
        if (pending.size() != 0) invalid()
        return stages.map { (path, byStage) ->
            GitConflictEntry(GitPath.of(path.toByteArray(Charsets.ISO_8859_1)), byStage[1]?.second, byStage[2]?.second, byStage[3]?.second,
                byStage.values.map { it.first }.toSet())
        }
    }

    /** A blob as text when it is valid UTF-8 within the bound; null otherwise (binary or large). */
    fun blobText(runner: GitCommandRunner, gitDir: Path, objectId: String): String? {
        val size = runner.run(GitInvocation("cat-file", listOf("-s", objectId), gitDir = gitDir, limits = LIMITS)).text.trim().toLongOrNull() ?: return null
        if (size > MAX_TEXT_BYTES) return null
        return utf8(runner.run(GitInvocation("cat-file", listOf("blob", objectId), gitDir = gitDir, limits = LIMITS)).stdout)
    }

    /**
     * A work-tree file as text, reading at most one byte beyond the bound, so an oversized file is
     * reported as unsupported without ever being loaded. An absent file is empty text.
     */
    fun fileText(file: Path): String? {
        if (!Files.isRegularFile(file, NOFOLLOW_LINKS)) return ""
        val bytes = Files.newInputStream(file, NOFOLLOW_LINKS).use { it.readNBytes(MAX_TEXT_BYTES + 1) }
        return utf8(bytes)
    }

    /** Publish only captured reviewed bytes, never ask Git to reopen mutable work-tree paths. */
    fun stageReviewed(runner: GitCommandRunner, gitDir: Path, workTree: Path, format: GitObjectFormat,
        files: List<Pair<GitPath, GitConflictFiles.Observation>>) {
        val zero = "0".repeat(checkNotNull(format.hexLength))
        val indexInfo = buildString {
            for ((path, current) in files) {
                val name = checkNotNull(path.exact)
                // Remove every unmerged stage, then add the captured stage-zero blob (or keep deleted).
                append("0 $zero\t$name\u0000")
                if (current.size != null) {
                    val blob = runner.run(GitInvocation("hash-object", listOf("-w", "--stdin"), gitDir = gitDir,
                        input = checkNotNull(current.text).toByteArray(Charsets.UTF_8), limits = LIMITS)).text.trim()
                    format.requireObjectId(blob)
                    append("${current.mode} $blob\t$name\u0000")
                }
            }
        }.toByteArray(Charsets.UTF_8)
        runner.run(GitInvocation("update-index", listOf("-z", "--index-info"), gitDir = gitDir, workTree = workTree,
            input = indexInfo, limits = LIMITS))
    }

    fun utf8(bytes: ByteArray): String? = if (bytes.size > MAX_TEXT_BYTES || bytes.any { it == 0.toByte() }) null else try {
        Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes)).toString()
    } catch (_: Exception) { null }

    /**
     * Digest of a work-tree file's current bytes, or `absent`; the concurrency token of a resolution.
     * Streamed with a bounded buffer, so an unsupported large file is never loaded to digest it.
     */
    fun contentDigest(file: Path): String {
        if (!Files.isRegularFile(file, NOFOLLOW_LINKS)) return "absent"
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        Files.newInputStream(file, NOFOLLOW_LINKS).use { input ->
            val buffer = ByteArray(64 * 1024)
            while (true) { val count = input.read(buffer); if (count < 0) break; digest.update(buffer, 0, count) }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    const val DEFAULT_MARKER_SIZE = 7

    /** The `conflict-marker-size` attribute in effect for [path]; Git's default when unset or invalid. */
    fun markerSize(runner: GitCommandRunner, gitDir: Path, workTree: Path, path: String): Int {
        val result = runner.run(GitInvocation("check-attr", listOf("-z", "conflict-marker-size", "--", path), gitDir = gitDir,
            workTree = workTree, limits = LIMITS))
        val value = result.stdout.toString(Charsets.UTF_8).split('\u0000').getOrNull(2)
        return value?.toIntOrNull()?.takeIf { it > 0 } ?: DEFAULT_MARKER_SIZE
    }

    /**
     * A conflict marker at a line start means the file is not resolved yet. Markers of the effective
     * [size] and of Git's default width are both detected.
     */
    fun hasMarkers(text: String, size: Int = DEFAULT_MARKER_SIZE): Boolean = text.lineSequence().any { line ->
        setOf(size, DEFAULT_MARKER_SIZE).any { width ->
            // Compare against the bounded line, never allocate an attribute-controlled marker string.
            width > 0 && line.length >= width && (
                listOf('<', '>', '|').any { marker ->
                    (line.length == width || line[width] == ' ') && (0 until width).all { line[it] == marker }
                } || (line.length == width && line.all { it == '=' }))
        }
    }
}
