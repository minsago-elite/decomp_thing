package decompengine.git

import java.io.IOException
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.time.Duration

/** Parsed `git version` numbers. The display form never carries vendor suffixes or build paths. */
data class GitVersion(val major: Int, val minor: Int, val patch: Int) : Comparable<GitVersion> {
    init { require(major in 0..999 && minor in 0..999 && patch in 0..999) }
    val display: String get() = "$major.$minor.$patch"
    override fun compareTo(other: GitVersion): Int = compareValuesBy(this, other, { it.major }, { it.minor }, { it.patch })

    companion object {
        /**
         * GIT_CONFIG_GLOBAL (2.32), repository ownership checks (2.35.2) and
         * `--initial-branch`/`--show-object-format` are required by the controlled environment.
         */
        val MINIMUM = GitVersion(2, 36, 0)

        fun parse(output: String): GitVersion? {
            val match = Regex("^git version ([0-9]{1,3})\\.([0-9]{1,3})(?:\\.([0-9]{1,3}))?(?:\\.[A-Za-z0-9]{1,32}){0,4}(?: \\([A-Za-z0-9 ._-]{1,64}\\))?$")
                .matchEntire(output.trim().lineSequence().firstOrNull() ?: return null) ?: return null
            return GitVersion(match.groupValues[1].toInt(), match.groupValues[2].toInt(), match.groupValues[3].ifEmpty { "0" }.toInt())
        }
    }
}

/** Startup observation. Unavailable states carry fixed public reason codes and messages only. */
sealed interface GitAvailability {
    val version: GitVersion?

    class Available internal constructor(val executable: Path, override val version: GitVersion) : GitAvailability {
        /** A runner bound to one prepared server-owned environment. */
        fun runner(environment: GitEnvironment): GitCommandRunner = GitCommandRunner(executable, environment)
    }

    data class Unavailable(val reasonCode: String, val message: String, override val version: GitVersion? = null) : GitAvailability {
        init { require(reasonCode in REASONS) }
        companion object {
            val REASONS = setOf("GIT_NOT_FOUND", "GIT_VERSION_UNSUPPORTED", "GIT_PROBE_FAILED", "GIT_RUNTIME_UNAVAILABLE")
        }
    }
}

/**
 * Server-owned directories that replace every user-controlled Git location: HOME, the global
 * configuration file, hook directory and init template directory are private and empty.
 */
class GitEnvironment private constructor(
    val root: Path,
    val home: Path = root.resolve("home"),
    val emptyFile: Path = root.resolve("empty-config"),
    val hooks: Path = root.resolve("hooks"),
    val templates: Path = root.resolve("templates"),
) {

    /** Child environment. Nothing is inherited from the server process except the executable's directory. */
    fun variables(executable: Path): Map<String, String> = linkedMapOf(
        "PATH" to listOf(executable.parent.toString(), "/usr/bin", "/bin").distinct().joinToString(":"),
        "HOME" to home.toString(),
        "XDG_CONFIG_HOME" to home.resolve(".config").toString(),
        "GIT_CONFIG_NOSYSTEM" to "1",
        "GIT_CONFIG_GLOBAL" to emptyFile.toString(),
        "GIT_ATTR_NOSYSTEM" to "1",
        "GIT_TERMINAL_PROMPT" to "0",
        "GIT_ASKPASS" to "",
        "SSH_ASKPASS" to "",
        "GIT_EDITOR" to "false",
        "GIT_SEQUENCE_EDITOR" to "false",
        "GIT_PAGER" to "cat",
        "PAGER" to "cat",
        "GIT_NO_REPLACE_OBJECTS" to "1",
        "GIT_OPTIONAL_LOCKS" to "0",
        "GIT_PROTOCOL_FROM_USER" to "0",
        "GIT_CEILING_DIRECTORIES" to root.toString(),
        "LC_ALL" to "C",
        "LANG" to "C",
        "TZ" to "UTC",
    )

    /**
     * Command-line configuration has the highest precedence, so these values also neutralize the
     * corresponding keys in any repository configuration. Filter drivers, diff helpers and other
     * named executables can only come from configuration; managed repositories are audited against
     * [GitConfigurationAudit] before Git runs in them.
     */
    fun configuration(): List<Pair<String, String>> = listOf(
        "core.hooksPath" to hooks.toString(),
        "core.fsmonitor" to "false",
        "core.untrackedCache" to "false",
        "core.askPass" to "",
        "core.pager" to "cat",
        "core.editor" to "false",
        "core.sshCommand" to "false",
        "core.symlinks" to "false",
        "core.autocrlf" to "false",
        "core.protectNTFS" to "true",
        "core.protectHFS" to "true",
        "core.attributesFile" to emptyFile.toString(),
        "core.excludesFile" to emptyFile.toString(),
        "credential.helper" to "",
        "protocol.allow" to "never",
        "submodule.recurse" to "false",
        "fetch.recurseSubmodules" to "false",
        "push.recurseSubmodules" to "no",
        "gc.auto" to "0",
        "gc.autoDetach" to "false",
        "maintenance.auto" to "false",
        "commit.gpgSign" to "false",
        "tag.gpgSign" to "false",
        "init.templateDir" to templates.toString(),
        "color.ui" to "never",
        "advice.detachedHead" to "false",
        "safe.bareRepository" to "explicit",
        "transfer.fsckObjects" to "true",
    )

    companion object {
        /**
         * Storage-free environment for the startup version probe only. A read-only server must not
         * create storage, so the probe uses no writable directory and `git version` reads no repository.
         */
        internal fun probe(): GitEnvironment = Path.of("/nonexistent-decomp-git").let { missing ->
            GitEnvironment(Path.of("/"), missing, Path.of("/dev/null"), missing, missing)
        }

        /** Create or verify the private runtime directories; existing content must still be empty. */
        fun prepare(root: Path): GitEnvironment {
            val absolute = root.toAbsolutePath().normalize()
            val environment = GitEnvironment(absolute)
            val owner = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))
            fun directory(path: Path) {
                if (!Files.exists(path, NOFOLLOW_LINKS)) Files.createDirectory(path, owner)
                if (!Files.isDirectory(path, NOFOLLOW_LINKS)) throw IOException("Git runtime directory is invalid")
            }
            directory(absolute)
            listOf(environment.home, environment.hooks, environment.templates).forEach { path ->
                directory(path)
                Files.newDirectoryStream(path).use { entries -> if (entries.iterator().hasNext()) throw IOException("Git runtime directory is not empty") }
            }
            if (!Files.exists(environment.emptyFile, NOFOLLOW_LINKS)) Files.createFile(environment.emptyFile)
            if (!Files.isRegularFile(environment.emptyFile, NOFOLLOW_LINKS) || Files.size(environment.emptyFile) != 0L) {
                throw IOException("Git runtime configuration is not empty")
            }
            return environment
        }
    }
}

/** Separate bounds for one process; production defaults are conservative and per call site. */
data class GitExecutionLimits(
    val timeout: Duration = Duration.ofSeconds(30),
    val maxStdoutBytes: Int = 1024 * 1024,
    val maxStderrBytes: Int = 64 * 1024,
    /** Hard and soft RLIMIT_AS, including mappings; null only for calls not requiring this bound. */
    val maxAddressSpaceBytes: Long? = null,
) {
    init {
        require(!timeout.isNegative && !timeout.isZero && timeout <= Duration.ofMinutes(10))
        require(maxStdoutBytes in 1..64 * 1024 * 1024 && maxStderrBytes in 1..1024 * 1024)
        require(maxAddressSpaceBytes == null || maxAddressSpaceBytes in 16L * 1024 * 1024..4L * 1024 * 1024 * 1024)
    }
}

class GitCommandException(val kind: Kind, message: String, val exitCode: Int? = null) : IOException(message) {
    enum class Kind { START_FAILED, TIMED_OUT, OUTPUT_LIMIT, FAILED, INTERRUPTED }
}

/** Captured output stays server-side; stderr in particular may contain host paths. */
class GitCommandResult internal constructor(
    val exitCode: Int,
    val stdout: ByteArray,
    private val stderr: ByteArray,
    val stdoutTruncated: Boolean,
) {
    val text: String get() = stdout.toString(Charsets.UTF_8)
    internal val diagnostic: String get() = stderr.toString(Charsets.UTF_8)
}

/**
 * One validated invocation. The runner adds every global option itself; callers can name only an
 * allowlisted subcommand followed by its arguments, which are passed as separate argv entries.
 */
data class GitInvocation(
    val subcommand: String,
    val arguments: List<String> = emptyList(),
    val gitDir: Path? = null,
    val workTree: Path? = null,
    val allowedExitCodes: Set<Int> = setOf(0),
    val truncateStdout: Boolean = false,
    val limits: GitExecutionLimits = GitExecutionLimits(),
    /** Bounded standard input, written once and closed; null keeps stdin closed. */
    val input: ByteArray? = null,
    /** Additional variables from a fixed allowlist (commit identity and dates only). */
    val variables: Map<String, String> = emptyMap(),
) {
    init {
        require(subcommand in SUBCOMMANDS) { "Git subcommand is not allowlisted" }
        require(arguments.size <= 256 && arguments.all { it.length <= MAX_ARGUMENT_LENGTH && '\u0000' !in it }) { "Git arguments are unbounded" }
        require(gitDir == null || gitDir.isAbsolute) { "Git directory must be absolute" }
        require(workTree == null || (workTree.isAbsolute && gitDir != null)) { "Git work tree requires an absolute path and Git directory" }
        require(allowedExitCodes.isNotEmpty() && allowedExitCodes.all { it in 0..255 })
        require(input == null || input.size <= 4 * 1024 * 1024) { "Git input is unbounded" }
        require(variables.keys.all { it in VARIABLES } && variables.values.all { it.length <= 512 && it.none(Char::isISOControl) }) {
            "Git variables are not allowlisted"
        }
    }

    companion object {
        const val MAX_ARGUMENT_LENGTH = 4096
        val SUBCOMMANDS = setOf(
            "version", "init", "config", "check-ref-format", "rev-parse", "symbolic-ref", "for-each-ref",
            "status", "read-tree", "fsck", "cat-file", "ls-files", "ls-tree", "check-ignore", "update-ref",
            "log", "diff", "diff-tree",
        )
        val VARIABLES = setOf("GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL", "GIT_AUTHOR_DATE",
            "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL", "GIT_COMMITTER_DATE")
    }
}

/** Runs the one trusted executable without a shell, a TTY, inherited environment or inherited config. */
class GitCommandRunner internal constructor(
    val executable: Path,
    val environment: GitEnvironment,
    private val memoryLimiter: Path? = listOf(Path.of("/usr/bin/prlimit"), Path.of("/bin/prlimit"))
        .firstOrNull { Files.isRegularFile(it) && Files.isExecutable(it) }?.toRealPath(),
) {
    fun argv(invocation: GitInvocation): List<String> = buildList {
        add(executable.toString())
        add("--no-pager"); add("--no-replace-objects")
        // check-ignore takes plain path names and refuses pathspec magic, including `literal`.
        if (invocation.subcommand != "check-ignore") add("--literal-pathspecs")
        environment.configuration().forEach { (key, value) -> add("-c"); add("$key=$value") }
        invocation.gitDir?.let { add("--git-dir=$it") }
        invocation.workTree?.let { add("--work-tree=$it") }
        add(invocation.subcommand)
        addAll(invocation.arguments)
    }

    fun run(invocation: GitInvocation): GitCommandResult {
        val command = argv(invocation)
        val boundedCommand = invocation.limits.maxAddressSpaceBytes?.let { bytes ->
            // Use only the fixed server utility, never repository data or request/PATH lookup.
            // prlimit execs Git under the bound; failure never falls back to unbounded Git.
            val launcher = memoryLimiter ?: throw GitCommandException(GitCommandException.Kind.START_FAILED,
                "The server cannot enforce the required Git memory bound.")
            listOf(launcher.toString(), "--as=$bytes:$bytes", "--core=0:0", "--") + command
        } ?: command
        val result = try {
            GitSessionProcess(boundedCommand, environment.variables(executable) + invocation.variables,
                invocation.workTree ?: invocation.gitDir ?: environment.root, invocation).execute()
        } catch (failure: LinkageError) {
            // Native containment is mandatory, never fall back to unowned ProcessBuilder children.
            throw GitCommandException(GitCommandException.Kind.START_FAILED, "Git process containment is unavailable.")
        }
        if (!result.stdoutTruncated && result.exitCode !in invocation.allowedExitCodes) {
            throw GitCommandException(GitCommandException.Kind.FAILED, "Git reported a failure.", result.exitCode)
        }
        return result
    }
}

/**
 * Locates and qualifies the trusted executable once, at startup. The first absolute `git` on the
 * server's PATH is resolved to its real path and used for the listener lifetime; requests never
 * select an executable.
 */
object GitRuntime {
    fun detect(
        candidates: List<Path> = pathCandidates(System.getenv("PATH")),
        minimum: GitVersion = GitVersion.MINIMUM,
    ): GitAvailability {
        val executable = candidates.asSequence().filter { it.isAbsolute }.mapNotNull { candidate ->
            try { candidate.toRealPath().takeIf { Files.isRegularFile(it) && Files.isExecutable(it) } } catch (_: IOException) { null }
        }.firstOrNull() ?: return GitAvailability.Unavailable("GIT_NOT_FOUND", "Git is not installed or not executable on the server.")
        val version = try {
            GitVersion.parse(GitCommandRunner(executable, GitEnvironment.probe())
                .run(GitInvocation("version", limits = GitExecutionLimits(Duration.ofSeconds(10), 4096, 4096))).text)
        } catch (_: GitCommandException) { null }
            ?: return GitAvailability.Unavailable("GIT_PROBE_FAILED", "The server's Git executable did not report a recognizable version.")
        if (version < minimum) {
            return GitAvailability.Unavailable("GIT_VERSION_UNSUPPORTED",
                "Git ${version.display} is older than the required ${minimum.display}.", version)
        }
        return GitAvailability.Available(executable, version)
    }

    fun pathCandidates(path: String?): List<Path> = (path ?: "").split(':').filter { it.startsWith("/") }
        .mapNotNull { directory -> try { Path.of(directory, "git") } catch (_: Exception) { null } }
}
