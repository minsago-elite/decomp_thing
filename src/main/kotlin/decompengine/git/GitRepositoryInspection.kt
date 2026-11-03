package decompengine.git

import java.io.IOException
import java.nio.file.FileVisitResult
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.SimpleFileVisitor
import java.nio.file.attribute.BasicFileAttributes
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
        GitManagedLayout.requireUnlinkedRepository(gitDir)
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
        val neutral = Files.isRegularFile(attributes, NOFOLLOW_LINKS) && Files.size(attributes) <= 4096 &&
            Files.readString(attributes) == GitManagedLayout.ATTRIBUTES
        if (!neutral) throw GitRepositoryException("REPOSITORY_CONFIG_UNTRUSTED",
            "The managed repository does not neutralize content conversions.")
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
    const val ATTRIBUTES = "* -text !eol -crlf -ident -filter !working-tree-encoding\n"
    private const val MAX_LAYOUT_ENTRIES = 100_000

    /**
     * Defense in depth, not storage admission: callers must own and lock the physical storage
     * against concurrent replacement and reject shared writable inodes when importing it.
     */
    fun requireUnlinkedDirectory(path: Path) {
        var directory: Path? = path.toAbsolutePath()
        while (directory != null) {
            if (!Files.isDirectory(directory, NOFOLLOW_LINKS)) {
                throw GitRepositoryException("REPOSITORY_UNSUPPORTED", "The managed directory is missing or linked.")
            }
            directory = directory.parent
        }
    }

    /** Inspect metadata without following links, including nested refs and loose object storage. */
    fun requireUnlinkedRepository(gitDir: Path) {
        requireUnlinkedDirectory(gitDir)
        val deadline = System.nanoTime() + Duration.ofSeconds(20).toNanos()
        var entries = 0
        fun checkEntry(attributes: BasicFileAttributes): FileVisitResult {
            if (!attributes.isDirectory && !attributes.isRegularFile) {
                throw GitRepositoryException("REPOSITORY_UNSUPPORTED", "The managed repository contains linked or special files.")
            }
            if (++entries > MAX_LAYOUT_ENTRIES || System.nanoTime() > deadline) {
                throw GitRepositoryException("REPOSITORY_UNAVAILABLE", "The repository layout could not be checked within its bounds.")
            }
            return FileVisitResult.CONTINUE
        }
        try {
            Files.walkFileTree(gitDir, object : SimpleFileVisitor<Path>() {
                override fun preVisitDirectory(dir: Path, attrs: BasicFileAttributes): FileVisitResult = checkEntry(attrs)
                override fun visitFile(file: Path, attrs: BasicFileAttributes): FileVisitResult = checkEntry(attrs)
            })
        } catch (_: IOException) {
            throw GitRepositoryException("REPOSITORY_UNSUPPORTED", "The managed repository layout could not be read.")
        }
    }

    fun prepare(gitDir: Path) {
        requireUnlinkedRepository(gitDir)
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
     * Display-only fingerprint of bounded porcelain status plus HEAD, NOT a source identity or
     * concurrency token. Further edits to an already-dirty path (or beyond the output bound) can
     * leave it unchanged. Mutation/provenance callers need a separately locked content snapshot.
     */
    val statusDigest: String,
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
        if (refName != null) {
            if (!refName.startsWith("refs/heads/") || !GitRefNames.isObservedRefName(refName) ||
                runner.run(GitInvocation("check-ref-format", listOf(refName), allowedExitCodes = setOf(0, 1), limits = READ)).exitCode != 0
            ) throw GitRepositoryException("REPOSITORY_UNSUPPORTED", "HEAD does not name a supported branch reference.")
        }
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

    fun refs(runner: GitCommandRunner, gitDir: Path, format: GitObjectFormat, head: GitHeadObservation? = null): Pair<List<GitRefObservation>, Boolean> {
        val output = runner.run(GitInvocation("for-each-ref", listOf("--count=${MAX_REFS + 1}", "--format=%(objectname) %(refname)",
            "refs/heads", "refs/tags"), gitDir = gitDir, limits = READ)).text
        val refs = output.lineSequence().filter { it.isNotEmpty() }.map { line ->
            val objectId = format.objectIdOrNull(line.substringBefore(' '))
            val name = line.substringAfter(' ', "")
            if (objectId == null || !GitRefNames.isObservedRefName(name)) throw GitRepositoryException("REPOSITORY_CORRUPT", "A reference has an invalid name or object ID.")
            GitRefObservation(name, objectId)
        }.toList()
        val truncated = refs.size > MAX_REFS
        val bounded = refs.take(MAX_REFS)
        val attached = head?.takeIf { it.state == GitHeadState.ATTACHED }?.let { GitRefObservation(it.refName!!, it.objectId!!) }
        if (attached != null && attached !in bounded) {
            if (refs.any { it.name == attached.name && it != attached } || !truncated) {
                throw GitRepositoryException("REPOSITORY_UNAVAILABLE", "HEAD and its branch could not be observed consistently.")
            }
            // The wire contract requires attached HEAD to match a listed ref, even on a bounded page.
            return (bounded.take(MAX_REFS - 1) + attached) to true
        }
        return bounded to truncated
    }

    /** Status never fetches, refreshes optional locks, descends into submodules or runs hooks. */
    fun inspect(runner: GitCommandRunner, gitDir: Path, workTree: Path): GitWorkspaceObservation {
        GitManagedLayout.requireUnlinkedDirectory(workTree)
        GitConfigurationAudit.requireManaged(runner, gitDir)
        try {
            val format = objectFormat(runner, gitDir)
            if (format == GitObjectFormat.UNKNOWN) throw GitRepositoryException("REPOSITORY_UNSUPPORTED", "The repository object format is not supported.")
            val head = head(runner, gitDir, format)
            val (refs, truncated) = refs(runner, gitDir, format, head)
            val status = runner.run(GitInvocation("status", listOf("--porcelain=v1", "-z", "--untracked-files=all",
                "--ignore-submodules=all", "--no-renames"), gitDir = gitDir, workTree = workTree, truncateStdout = true, limits = READ))
            val digest = MessageDigest.getInstance("SHA-256").apply {
                update("git-workspace-status-v1\n${head.state.wireName}\n${head.refName ?: ""}\n${head.objectId ?: ""}\n${status.stdoutTruncated}\n".toByteArray())
                update(status.stdout)
            }.digest().joinToString("") { "%02x".format(it) }
            return GitWorkspaceObservation(format, head, refs, truncated, status.stdout.isNotEmpty() || status.stdoutTruncated, digest)
        } catch (failure: GitCommandException) {
            throw GitRepositoryException(if (failure.kind == GitCommandException.Kind.FAILED) "REPOSITORY_CORRUPT" else "REPOSITORY_UNAVAILABLE",
                "The repository could not be read within its bounds.")
        }
    }
}
