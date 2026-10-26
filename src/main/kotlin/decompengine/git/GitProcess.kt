package decompengine.git

import java.io.IOException
import java.io.InputStream
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.time.Duration
import java.util.concurrent.TimeUnit

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
) {
    init {
        require(!timeout.isNegative && !timeout.isZero && timeout <= Duration.ofMinutes(10))
        require(maxStdoutBytes in 1..64 * 1024 * 1024 && maxStderrBytes in 1..1024 * 1024)
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
) {
    init {
        require(subcommand in SUBCOMMANDS) { "Git subcommand is not allowlisted" }
        require(arguments.size <= 256 && arguments.all { it.length <= 4096 && '\u0000' !in it }) { "Git arguments are unbounded" }
        require(gitDir == null || gitDir.isAbsolute) { "Git directory must be absolute" }
        require(workTree == null || (workTree.isAbsolute && gitDir != null)) { "Git work tree requires an absolute path and Git directory" }
        require(allowedExitCodes.isNotEmpty() && allowedExitCodes.all { it in 0..255 })
    }

    companion object {
        val SUBCOMMANDS = setOf(
            "version", "init", "config", "check-ref-format", "rev-parse", "symbolic-ref", "for-each-ref",
            "status", "read-tree", "fsck", "cat-file", "ls-files", "ls-tree", "check-ignore", "update-ref",
        )
    }
}

/** Runs the one trusted executable without a shell, a TTY, inherited environment or inherited config. */
class GitCommandRunner internal constructor(val executable: Path, val environment: GitEnvironment) {
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
        val builder = ProcessBuilder(argv(invocation))
            .directory((invocation.workTree ?: invocation.gitDir ?: environment.root).toFile())
            .redirectInput(ProcessBuilder.Redirect.PIPE)
        builder.environment().clear()
        builder.environment().putAll(environment.variables(executable))
        val process = try { builder.start() } catch (failure: IOException) {
            throw GitCommandException(GitCommandException.Kind.START_FAILED, "Git could not be started.")
        }
        try {
            process.outputStream.close()
            val stdout = BoundedCapture(process.inputStream, invocation.limits.maxStdoutBytes)
            val stderr = BoundedCapture(process.errorStream, invocation.limits.maxStderrBytes)
            val readers = listOf(Thread.ofVirtual().start(stdout), Thread.ofVirtual().start(stderr))
            val deadline = System.nanoTime() + invocation.limits.timeout.toNanos()
            while (process.isAlive) {
                if (stdout.overflowed && invocation.truncateStdout) break
                if (stdout.overflowed || stderr.overflowed) {
                    terminate(process)
                    throw GitCommandException(GitCommandException.Kind.OUTPUT_LIMIT, "Git output exceeded its bound.")
                }
                val remaining = deadline - System.nanoTime()
                if (remaining <= 0) {
                    terminate(process)
                    throw GitCommandException(GitCommandException.Kind.TIMED_OUT, "Git did not finish within its time bound.")
                }
                process.waitFor(minOf(remaining, TimeUnit.MILLISECONDS.toNanos(20)), TimeUnit.NANOSECONDS)
            }
            if (stdout.overflowed && invocation.truncateStdout) terminate(process)
            readers.forEach { it.join(TimeUnit.NANOSECONDS.toMillis(maxOf(deadline - System.nanoTime(), 0)) + 1000) }
            if (readers.any { it.isAlive }) {
                terminate(process)
                throw GitCommandException(GitCommandException.Kind.TIMED_OUT, "Git output did not close within its time bound.")
            }
            // The readers can still be draining when the process exits, so only their final state
            // decides truncation. Stderr keeps its own limit either way.
            val truncated = stdout.overflowed && invocation.truncateStdout
            if (stderr.overflowed || (stdout.overflowed && !truncated)) {
                throw GitCommandException(GitCommandException.Kind.OUTPUT_LIMIT, "Git output exceeded its bound.")
            }
            val exit = if (truncated) -1 else process.exitValue()
            if (!truncated && exit !in invocation.allowedExitCodes) {
                throw GitCommandException(GitCommandException.Kind.FAILED, "Git reported a failure.", exit)
            }
            return GitCommandResult(exit, stdout.bytes(), stderr.bytes(), truncated)
        } catch (interrupted: InterruptedException) {
            terminate(process)
            Thread.currentThread().interrupt()
            throw GitCommandException(GitCommandException.Kind.INTERRUPTED, "Git was interrupted.")
        } finally {
            if (process.isAlive) terminate(process)
        }
    }

    private fun terminate(process: Process) {
        process.descendants().forEach { it.destroyForcibly() }
        process.destroyForcibly()
        process.waitFor(5, TimeUnit.SECONDS)
    }

    /** Keeps at most [limit] bytes and records overflow; it keeps draining so the child cannot block. */
    private class BoundedCapture(private val input: InputStream, private val limit: Int) : Runnable {
        private val buffer = java.io.ByteArrayOutputStream()
        @Volatile var overflowed = false
            private set

        override fun run() {
            try {
                input.use { stream ->
                    val chunk = ByteArray(8192)
                    while (true) {
                        val count = stream.read(chunk)
                        if (count < 0) break
                        synchronized(buffer) {
                            val room = limit - buffer.size()
                            if (count > room) { buffer.write(chunk, 0, maxOf(room, 0)); overflowed = true }
                            else buffer.write(chunk, 0, count)
                        }
                    }
                }
            } catch (_: IOException) {
                // The process was terminated; the caller reports the bound that caused it.
            }
        }

        fun bytes(): ByteArray = synchronized(buffer) { buffer.toByteArray() }
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
