package decompengine.git

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.time.Duration
import java.time.Instant

/**
 * A publication intent (#599, #601), written before Git contacts the remote and kept until the
 * outcome is known. A retained intent means the remote state is unconfirmed: it blocks a retry to
 * the same branch until it is reconciled against the remote.
 */
data class GitPushIntent(
    val operationId: String,
    val remoteId: String,
    val branch: String,
    val expectedObjectId: String?,
    val pushedObjectId: String,
    val startedAt: Instant,
)

/** Outcome Git reported for the one pushed ref. */
enum class GitPushResult { PUBLISHED, UP_TO_DATE, REJECTED_NON_FAST_FORWARD, REJECTED_REMOTE_CHANGED, REJECTED }

internal object GitPushes {
    const val DIRECTORY = "push-intents"
    private val READ = GitExecutionLimits(Duration.ofSeconds(60), 256 * 1024, 64 * 1024)

    fun write(directory: Path, intent: GitPushIntent) {
        val intents = GitStorage.directories(directory, DIRECTORY)
        GitStorage.replaceAtomically(intents.resolve("${intent.operationId}.json"), buildJsonObject {
            put("operationId", intent.operationId); put("remoteId", intent.remoteId); put("branch", intent.branch)
            put("expectedObjectId", intent.expectedObjectId?.let(::JsonPrimitive) ?: JsonNull)
            put("pushedObjectId", intent.pushedObjectId); put("startedAt", intent.startedAt.toString())
        }.toString().toByteArray())
    }

    fun delete(directory: Path, operationId: String) { Files.deleteIfExists(directory.resolve(DIRECTORY).resolve("$operationId.json")) }

    fun list(directory: Path): List<GitPushIntent> {
        val intents = directory.resolve(DIRECTORY)
        if (!Files.isDirectory(intents, NOFOLLOW_LINKS)) return emptyList()
        return Files.newDirectoryStream(intents).use { entries ->
            entries.filter { it.fileName.toString().matches(Regex("operation_[0-9a-f]{32}\\.json")) }.take(64).map { file ->
                try {
                    val value = Json.parseToJsonElement(GitStorage.read(file, 4096).toString(Charsets.UTF_8)).jsonObject
                    fun text(name: String) = value.getValue(name).jsonPrimitive.content
                    GitPushIntent(text("operationId"), text("remoteId"), text("branch"),
                        value.getValue("expectedObjectId").takeIf { it != JsonNull }?.jsonPrimitive?.content, text("pushedObjectId"),
                        Instant.parse(text("startedAt")))
                } catch (_: Exception) {
                    throw ManagedGitException("STORAGE_FAILED", "A push intent record is unreadable. Preserve storage and inspect it.")
                }
            }
        }
    }

    /** The remote's current object for one branch, read with `ls-remote`; null when it does not exist. */
    fun remoteObject(runner: GitCommandRunner, location: GitRemoteLocation, policy: GitRemotePolicy, branch: String, format: GitObjectFormat): String? {
        val ref = "refs/heads/$branch"
        val result = runner.run(GitInvocation("ls-remote", listOf("--", location.url, ref), limits = READ,
            transport = GitTransports.context(location, policy)))
        return result.text.lineSequence().mapNotNull { line ->
            val parts = line.split('\t')
            if (parts.size == 2 && parts[1] == ref) format.objectIdOrNull(parts[0]) else null
        }.firstOrNull()
    }

    /**
     * Push exactly one object to one branch without `+`, `--force` or deletion, so the remote
     * refuses a non-fast-forward itself. Hooks, signing and submodule recursion are off.
     */
    fun push(runner: GitCommandRunner, gitDir: Path, location: GitRemoteLocation, policy: GitRemotePolicy, objectId: String,
        branch: String): GitPushResult {
        val result = runner.run(GitInvocation("push", listOf("--porcelain", "--no-verify", "--signed=false", "--no-recurse-submodules",
            "--no-follow-tags", "--no-atomic", "--", location.url, "$objectId:refs/heads/$branch"), gitDir = gitDir,
            limits = GitTransfers.limits(policy), transport = GitTransports.context(location, policy), allowedExitCodes = setOf(0, 1)))
        val line = result.text.lineSequence().firstOrNull { it.contains("\t") && it.contains(":refs/heads/$branch") }
        return when {
            line == null -> if (result.exitCode == 0) GitPushResult.PUBLISHED else GitPushResult.REJECTED
            line.startsWith("=") -> GitPushResult.UP_TO_DATE
            line.startsWith(" ") || line.startsWith("*") -> GitPushResult.PUBLISHED
            line.startsWith("!") && "non-fast-forward" in line -> GitPushResult.REJECTED_NON_FAST_FORWARD
            line.startsWith("!") && ("fetch first" in line || "stale info" in line) -> GitPushResult.REJECTED_REMOTE_CHANGED
            else -> GitPushResult.REJECTED
        }
    }

    fun isAncestor(runner: GitCommandRunner, gitDir: Path, ancestor: String, descendant: String): Boolean =
        runner.run(GitInvocation("merge-base", listOf("--is-ancestor", ancestor, descendant), gitDir = gitDir,
            allowedExitCodes = setOf(0, 1, 128), limits = READ)).exitCode == 0

    /** Commits that a push would publish, newest first, bounded. */
    fun outgoing(runner: GitCommandRunner, gitDir: Path, local: String, remote: String?, limit: Int): Pair<List<Pair<String, String>>, Long> {
        val range = if (remote == null) listOf(local) else listOf(local, "^$remote")
        val count = runner.run(GitInvocation("rev-list", listOf("--count") + range, gitDir = gitDir, limits = READ)).text.trim().toLong()
        val listed = runner.run(GitInvocation("log", listOf("--format=%H%x00%s", "-n", limit.toString()) + range + listOf("--"), gitDir = gitDir, limits = READ))
        return listed.text.lineSequence().filter { it.isNotEmpty() }.mapNotNull { line ->
            val parts = line.split('\u0000', limit = 2)
            if (parts.size == 2) parts[0] to parts[1].take(200) else null
        }.toList() to count
    }
}
