package decompengine.git

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.TimeUnit

/**
 * Test-only history construction. Production code never commits through this helper; it uses a
 * fixed identity, no user configuration and disabled hooks so fixture setup cannot observe the
 * developer machine. Every root lives under the Gradle-provided temporary directory.
 */
internal class GitTestRepositories : AutoCloseable {
    val root: Path = Files.createTempDirectory("git adapter ünïcode ")
    private val home: Path = Files.createDirectory(root.resolve("fixture-home"))
    val environment: GitEnvironment = GitEnvironment.prepare(root.resolve("runtime"))
    val runner: GitCommandRunner = (GitRuntime.detect() as GitAvailability.Available).runner(environment)

    /** Raw fixture Git: argv only, fixture HOME, no hooks. Returns stdout. */
    fun git(vararg args: String, cwd: Path = root, expect: Int = 0): String {
        val process = ProcessBuilder(listOf("git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgSign=false", *args))
            .directory(cwd.toFile()).redirectErrorStream(true).also { builder ->
                builder.environment().clear()
                builder.environment().putAll(mapOf(
                    "PATH" to (System.getenv("PATH") ?: "/usr/bin:/bin"), "HOME" to home.toString(), "LC_ALL" to "C",
                    "GIT_CONFIG_NOSYSTEM" to "1", "GIT_CONFIG_GLOBAL" to "/dev/null", "GIT_TERMINAL_PROMPT" to "0",
                    "GIT_AUTHOR_NAME" to "Fixture Author", "GIT_AUTHOR_EMAIL" to "fixture@example.invalid",
                    "GIT_COMMITTER_NAME" to "Fixture Committer", "GIT_COMMITTER_EMAIL" to "fixture@example.invalid",
                    "GIT_AUTHOR_DATE" to "2026-01-01T00:00:00Z", "GIT_COMMITTER_DATE" to "2026-01-01T00:00:00Z",
                ))
            }.start()
        process.outputStream.close()
        val output = process.inputStream.readBytes().toString(Charsets.UTF_8)
        check(process.waitFor(30, TimeUnit.SECONDS)) { "fixture Git timed out" }
        check(process.exitValue() == expect) { "fixture git ${args.firstOrNull()} exited ${process.exitValue()}: $output" }
        return output
    }

    /** Bare managed-style repository created through the adapter, plus a separate work tree. */
    fun managed(name: String, branch: String = "trunk", format: String = "sha1"): Pair<Path, Path> {
        val gitDir = root.resolve("$name.git")
        val workTree = Files.createDirectories(root.resolve("$name work"))
        runner.run(GitInvocation("init", listOf("--quiet", "--bare", "--initial-branch=$branch", "--object-format=$format", gitDir.toString())))
        GitManagedLayout.prepare(gitDir)
        return gitDir to workTree
    }

    fun commitAll(gitDir: Path, workTree: Path, message: String): String {
        git("--git-dir=$gitDir", "--work-tree=$workTree", "add", "-A", "--", ".")
        git("--git-dir=$gitDir", "--work-tree=$workTree", "commit", "-q", "-m", message)
        return git("--git-dir=$gitDir", "rev-parse", "HEAD").trim()
    }

    /** Executable script that leaves [marker] behind if anything ever runs it. */
    fun tripwire(name: String, marker: Path): Path {
        val script = root.resolve(name)
        Files.writeString(script, "#!/bin/sh\necho ran >> '${marker}'\ncat\n")
        Files.setPosixFilePermissions(script, PosixFilePermissions.fromString("rwx------"))
        return script
    }

    override fun close() { root.toFile().deleteRecursively() }
}
