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
data class GitConflictEntry(val path: GitPath, val baseObjectId: String?, val oursObjectId: String?, val theirsObjectId: String?)

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
        val result = runner.run(GitInvocation("merge", listOf("-q", "--no-verify", "--no-gpg-sign", "--no-edit", "--no-stat", "--no-log",
            "--no-squash", "--no-signoff", "--no-autostash", "--no-rerere-autoupdate", "--no-progress") + mode + listOf(target),
            gitDir = gitDir, workTree = workTree, variables = identity, allowedExitCodes = setOf(0, 1, 2, 128), limits = LIMITS))
        if (result.exitCode == 0) return false
        if (mergeInProgress(gitDir)) return true
        throw GitOperationRefusal("MERGE_REFUSED", "Git refused the integration, for example because a local file would be overwritten. Nothing was changed.")
    }

    fun abort(runner: GitCommandRunner, gitDir: Path, workTree: Path) {
        val result = runner.run(GitInvocation("merge", listOf("--abort"), gitDir = gitDir, workTree = workTree, allowedExitCodes = setOf(0, 128), limits = LIMITS))
        if (result.exitCode != 0) throw GitOperationRefusal("ABORT_REFUSED", "Git could not abort the merge. Inspect the work tree before any new request.")
    }

    /** Every unmerged path with the blob of each stage that exists. */
    fun conflicts(runner: GitCommandRunner, gitDir: Path, workTree: Path): List<GitConflictEntry> {
        val result = runner.run(GitInvocation("ls-files", listOf("-u", "-z"), gitDir = gitDir, workTree = workTree, limits = LIMITS))
        val stages = LinkedHashMap<String, MutableMap<Int, String>>()
        for (record in result.stdout.toString(Charsets.ISO_8859_1).split('\u0000')) {
            if (record.isEmpty()) continue
            val (meta, path) = record.split('\t', limit = 2).takeIf { it.size == 2 }?.let { it[0] to it[1] } ?: continue
            val parts = meta.split(' ')
            if (parts.size != 3) continue
            stages.getOrPut(path) { mutableMapOf() }[parts[2].toInt()] = parts[1]
        }
        return stages.map { (path, byStage) ->
            GitConflictEntry(GitPath.of(path.toByteArray(Charsets.ISO_8859_1)), byStage[1], byStage[2], byStage[3])
        }
    }

    /** A blob as text when it is valid UTF-8 within the bound; null otherwise (binary or large). */
    fun blobText(runner: GitCommandRunner, gitDir: Path, objectId: String): String? {
        val size = runner.run(GitInvocation("cat-file", listOf("-s", objectId), gitDir = gitDir, limits = LIMITS)).text.trim().toLongOrNull() ?: return null
        if (size > MAX_TEXT_BYTES) return null
        return utf8(runner.run(GitInvocation("cat-file", listOf("blob", objectId), gitDir = gitDir, limits = LIMITS)).stdout)
    }

    fun utf8(bytes: ByteArray): String? = if (bytes.size > MAX_TEXT_BYTES || bytes.any { it == 0.toByte() }) null else try {
        Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes)).toString()
    } catch (_: Exception) { null }

    /** Digest of a work-tree file's current bytes, or `absent`; the concurrency token of a resolution. */
    fun contentDigest(file: Path): String =
        if (!Files.isRegularFile(file, NOFOLLOW_LINKS)) "absent" else GitStorage.sha256(Files.readAllBytes(file))

    /** A conflict marker at a line start means the file is not resolved yet. */
    fun hasMarkers(text: String): Boolean = text.lineSequence().any { it.startsWith("<<<<<<< ") || it.startsWith(">>>>>>> ") || it == "=======" }
}
