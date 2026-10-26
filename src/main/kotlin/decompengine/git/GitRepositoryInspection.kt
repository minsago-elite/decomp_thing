package decompengine.git

import java.net.URI
import java.nio.file.Files
import java.nio.file.NoSuchFileException
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.security.MessageDigest
import java.time.Duration

class GitRepositoryException(val code: String, message: String) : Exception(message) {
    init { require(code in CODES) }
    companion object {
        val CODES = setOf("REPOSITORY_UNSUPPORTED", "REPOSITORY_CORRUPT", "REPOSITORY_CONFIG_UNTRUSTED", "REPOSITORY_UNAVAILABLE")
    }
}

/**
 * Repository configuration is data until audited. Git reads a repository's own `config` whenever
 * it runs there, and only configuration can name an executable (filters, diff/merge drivers,
 * credential helpers, fsmonitor, pagers, includes). A managed repository's configuration is
 * written by the server and must contain only these inert keys before any command runs in it.
 */
object GitConfigurationAudit {
    private const val MAX_CONFIG_BYTES = 64L * 1024
    private val MANAGED_KEYS = setOf(
        "core.repositoryformatversion", "core.filemode", "core.bare", "core.ignorecase", "core.precomposeunicode",
        "core.logallrefupdates", "extensions.objectformat", "user.name", "user.email", "user.useconfigonly",
    )

    /** Reads one config file without includes. The file is never treated as a repository. */
    fun read(runner: GitCommandRunner, file: Path): List<Pair<String, String>> {
        if (!Files.isRegularFile(file, NOFOLLOW_LINKS) || Files.size(file) > MAX_CONFIG_BYTES) {
            throw GitRepositoryException("REPOSITORY_UNSUPPORTED", "The repository configuration is missing, linked or too large.")
        }
        val result = try {
            runner.run(GitInvocation("config", listOf("--file", file.toAbsolutePath().toString(), "--no-includes", "--null", "--list"),
                allowedExitCodes = setOf(0, 1), limits = GitExecutionLimits(Duration.ofSeconds(10), 256 * 1024, 16 * 1024)))
        } catch (_: GitCommandException) {
            throw GitRepositoryException("REPOSITORY_CORRUPT", "The repository configuration could not be parsed.")
        }
        if (result.exitCode != 0 && result.stdout.isNotEmpty()) throw GitRepositoryException("REPOSITORY_CORRUPT", "The repository configuration could not be parsed.")
        return result.text.split('\u0000').filter { it.isNotEmpty() }.map { entry ->
            entry.substringBefore('\n').lowercase() to entry.substringAfter('\n', "")
        }
    }

    fun requireManaged(runner: GitCommandRunner, gitDir: Path) {
        val entries = read(runner, gitDir.resolve("config"))
        val values = entries.groupBy({ it.first }, { it.second })
        if (entries.any { it.first !in MANAGED_KEYS } || values.values.any { it.size != 1 } ||
            values["core.bare"] != listOf("true") || values["core.repositoryformatversion"]?.single() !in setOf("0", "1") ||
            values["extensions.objectformat"]?.single().let { it != null && it !in setOf("sha1", "sha256") }
        ) throw GitRepositoryException("REPOSITORY_CONFIG_UNTRUSTED", "The managed repository configuration contains unreviewed settings.")
        for (forbidden in listOf("commondir", "objects/info/alternates", "objects/info/http-alternates", "shallow")) {
            if (Files.exists(gitDir.resolve(forbidden), NOFOLLOW_LINKS)) {
                throw GitRepositoryException("REPOSITORY_UNSUPPORTED", "The managed repository links outside its own storage.")
            }
        }
        val attributes = gitDir.resolve("info").resolve("attributes")
        val content = if (Files.isDirectory(attributes.parent, NOFOLLOW_LINKS) &&
            Files.isRegularFile(attributes, NOFOLLOW_LINKS) && Files.size(attributes) <= 4096) Files.readString(attributes) else null
        when (content) {
            GitManagedLayout.ATTRIBUTES -> Unit
            // Upgrade only the exact previously audited server layout, never arbitrary attributes.
            GitManagedLayout.LEGACY_ATTRIBUTES -> GitManagedLayout.upgradeAttributes(gitDir)
            else -> throw GitRepositoryException("REPOSITORY_CONFIG_UNTRUSTED",
                "The managed repository does not neutralize content conversions and diff attributes.")
        }
    }
}

/**
 * Server-owned files in every managed Git directory. Built-in attribute conversions (`text`/`eol`
 * line endings, `ident` expansion, `working-tree-encoding`) need no configured driver, so the
 * repository's own `.gitattributes` could otherwise change checked-out bytes. `info/attributes`
 * has the highest attribute precedence, and this file unsets every converting attribute for all
 * paths, so checkout and status always see the exact blob bytes.
 */
object GitManagedLayout {
    internal const val LEGACY_ATTRIBUTES = "* -text !eol -crlf -ident -filter !working-tree-encoding\n"
    // Unspecified diff restores Git's automatic binary detection, overriding source `diff` rules.
    const val ATTRIBUTES = "* -text !eol -crlf -ident -filter !working-tree-encoding !diff\n"

    internal fun upgradeAttributes(gitDir: Path) {
        val attributes = gitDir.resolve("info/attributes")
        val temporary = Files.createTempFile(attributes.parent, ".attributes-upgrade-", ".tmp")
        try {
            Files.writeString(temporary, ATTRIBUTES)
            Files.move(temporary, attributes, java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                java.nio.file.StandardCopyOption.REPLACE_EXISTING)
        } finally { Files.deleteIfExists(temporary) }
    }

    fun prepare(gitDir: Path) {
        val info = gitDir.resolve("info")
        if (!Files.exists(info, NOFOLLOW_LINKS)) Files.createDirectory(info)
        if (!Files.isDirectory(info, NOFOLLOW_LINKS)) throw GitRepositoryException("REPOSITORY_UNSUPPORTED", "The managed repository layout is invalid.")
        for ((name, content) in listOf("attributes" to ATTRIBUTES, "exclude" to GitTrackingPolicy.excludeFile())) {
            val temporary = info.resolve(".$name.tmp")
            Files.deleteIfExists(temporary)
            Files.writeString(temporary, content)
            Files.move(temporary, info.resolve(name), java.nio.file.StandardCopyOption.ATOMIC_MOVE, java.nio.file.StandardCopyOption.REPLACE_EXISTING)
        }
    }
}

enum class GitHeadState(val wireName: String) { ATTACHED("attached"), DETACHED("detached"), UNBORN("unborn") }

/** HEAD as observed. An attached or unborn HEAD names its branch; only attached and detached name an object. */
data class GitHeadObservation(val state: GitHeadState, val refName: String?, val objectId: String?) {
    init {
        when (state) {
            GitHeadState.ATTACHED -> require(refName != null && objectId != null)
            GitHeadState.DETACHED -> require(refName == null && objectId != null)
            GitHeadState.UNBORN -> require(refName != null && objectId == null)
        }
    }
}

data class GitRefObservation(val name: String, val objectId: String)

/** One bounded read of a managed repository and its registered work tree. */
data class GitWorkspaceObservation(
    val objectFormat: GitObjectFormat,
    val head: GitHeadObservation,
    val refs: List<GitRefObservation>,
    val refsTruncated: Boolean,
    val dirty: Boolean,
    /**
     * SHA-256 of HEAD, every non-ignored status entry (with its index blob and the work-tree file's
     * size and modification time) and completeness, so any observed change produces a new value.
     */
    val statusDigest: String,
    val status: GitStatusSnapshot = GitStatusSnapshot(emptyList(), true),
)

object GitRepositoryInspector {
    const val MAX_REFS = 200
    private val READ = GitExecutionLimits(Duration.ofSeconds(20), 256 * 1024, 16 * 1024)

    fun objectFormat(runner: GitCommandRunner, gitDir: Path): GitObjectFormat = GitObjectFormat.fromGit(
        runner.run(GitInvocation("rev-parse", listOf("--show-object-format"), gitDir = gitDir, limits = READ)).text)

    /** HEAD without assuming a branch name. A missing commit for a symbolic HEAD is an unborn branch. */
    fun head(runner: GitCommandRunner, gitDir: Path, format: GitObjectFormat): GitHeadObservation {
        val symbolic = runner.run(GitInvocation("symbolic-ref", listOf("-q", "HEAD"), gitDir = gitDir, allowedExitCodes = setOf(0, 1), limits = READ))
        val refName = symbolic.text.trim().takeIf { symbolic.exitCode == 0 }
        if (refName != null && !GitRefNames.isObservedRefName(refName)) throw GitRepositoryException("REPOSITORY_UNSUPPORTED", "HEAD names an unsupported reference.")
        val resolved = runner.run(GitInvocation("rev-parse", listOf("-q", "--verify", "HEAD^{commit}"), gitDir = gitDir,
            allowedExitCodes = setOf(0, 1), limits = READ))
        val objectId = if (resolved.exitCode == 0) format.objectIdOrNull(resolved.text.trim())
            ?: throw GitRepositoryException("REPOSITORY_CORRUPT", "HEAD does not resolve to a full object ID for this repository.") else null
        return when {
            refName != null && objectId != null -> GitHeadObservation(GitHeadState.ATTACHED, refName, objectId)
            refName != null -> {
                // A branch whose ref exists but does not resolve to a commit is corrupt, not unborn.
                val exists = runner.run(GitInvocation("rev-parse", listOf("-q", "--verify", refName), gitDir = gitDir, allowedExitCodes = setOf(0, 1), limits = READ))
                if (exists.exitCode == 0) throw GitRepositoryException("REPOSITORY_CORRUPT", "HEAD names a reference that is not a commit.")
                GitHeadObservation(GitHeadState.UNBORN, refName, null)
            }
            objectId != null -> GitHeadObservation(GitHeadState.DETACHED, null, objectId)
            else -> throw GitRepositoryException("REPOSITORY_CORRUPT", "A detached HEAD does not name a commit.")
        }
    }

    fun refs(runner: GitCommandRunner, gitDir: Path, format: GitObjectFormat): Pair<List<GitRefObservation>, Boolean> {
        val output = runner.run(GitInvocation("for-each-ref", listOf("--count=${MAX_REFS + 1}", "--format=%(objectname) %(refname)",
            "refs/heads", "refs/tags"), gitDir = gitDir, limits = READ)).text
        val refs = output.lineSequence().filter { it.isNotEmpty() }.map { line ->
            val objectId = format.objectIdOrNull(line.substringBefore(' '))
            val name = line.substringAfter(' ', "")
            if (objectId == null || !GitRefNames.isObservedRefName(name)) throw GitRepositoryException("REPOSITORY_CORRUPT", "A reference has an invalid name or object ID.")
            GitRefObservation(name, objectId)
        }.toList()
        return refs.take(MAX_REFS) to (refs.size > MAX_REFS)
    }

    /** Status never fetches, refreshes optional locks, descends into submodules or runs hooks. */
    fun inspect(runner: GitCommandRunner, gitDir: Path, workTree: Path): GitWorkspaceObservation {
        GitConfigurationAudit.requireManaged(runner, gitDir)
        try {
            val format = objectFormat(runner, gitDir)
            if (format == GitObjectFormat.UNKNOWN) throw GitRepositoryException("REPOSITORY_UNSUPPORTED", "The repository object format is not supported.")
            val head = head(runner, gitDir, format)
            val (refs, truncated) = refs(runner, gitDir, format)
            val status = GitReads.status(runner, gitDir, workTree)
            val relevant = status.entries.filter { !it.ignored }
            val digest = MessageDigest.getInstance("SHA-256").apply {
                update("git-workspace-status-v2\n${head.state.wireName}\n${head.refName ?: ""}\n${head.objectId ?: ""}\n${status.complete}\n".toByteArray())
                for (entry in relevant) {
                    update(entry.path.bytes); update(0)
                    update("${entry.originalPath?.display ?: ""}\u0000${entry.staged}\u0000${entry.unstaged}\u0000${entry.untracked}\u0000${entry.conflict}\u0000${entry.indexObjectId ?: ""}\u0000${entry.indexMode ?: ""}\u0000${entry.worktreeMode ?: ""}\u0000".toByteArray())
                    // Re-editing an already modified file changes no status code; its size and time do.
                    val stat = try {
                        // URI percent escapes preserve native filename bytes on Unix, unlike a
                        // lossy UTF-8 String. Other providers must fail rather than hash a stable
                        // sentinel for a name they cannot represent.
                        val root = workTree.toAbsolutePath().normalize()
                        val file = entry.path.exact?.let(root::resolve) ?: Path.of(URI(
                            root.toUri().toASCIIString().trimEnd('/') + "/" + entry.path.bytes.joinToString("") {
                                if (it == '/'.code.toByte()) "/" else "%%%02X".format(it.toInt() and 0xff)
                            }))
                        if (!file.normalize().startsWith(root) || file.normalize() == root) throw IllegalArgumentException()
                        Files.readAttributes(file, java.nio.file.attribute.BasicFileAttributes::class.java, NOFOLLOW_LINKS)
                    } catch (_: NoSuchFileException) { null } catch (_: Exception) {
                        throw GitRepositoryException("REPOSITORY_UNAVAILABLE", "A work-tree file could not be observed exactly.")
                    }
                    update("${stat?.size() ?: -1}\u0000${stat?.lastModifiedTime()?.toInstant() ?: ""}\n".toByteArray())
                }
            }.digest().joinToString("") { "%02x".format(it) }
            return GitWorkspaceObservation(format, head, refs, truncated, relevant.isNotEmpty() || !status.complete, digest, status)
        } catch (failure: GitCommandException) {
            throw GitRepositoryException(if (failure.kind == GitCommandException.Kind.FAILED) "REPOSITORY_CORRUPT" else "REPOSITORY_UNAVAILABLE",
                "The repository could not be read within its bounds.")
        }
    }
}
