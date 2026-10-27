package decompengine.git

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.time.Duration
import kotlin.io.path.exists
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class GitAdapterTest {
    private fun fakeGit(directory: Path, body: String): Path {
        val script = Files.createDirectories(directory).resolve("git")
        Files.writeString(script, "#!/bin/sh\n$body\n")
        Files.setPosixFilePermissions(script, PosixFilePermissions.fromString("rwx------"))
        return script
    }

    @Test fun `version output is parsed without vendor suffixes`() {
        assertEquals(GitVersion(2, 56, 0), GitVersion.parse("git version 2.56.0\n"))
        assertEquals(GitVersion(2, 39, 3), GitVersion.parse("git version 2.39.3 (Apple Git-146)"))
        assertEquals(GitVersion(2, 45, 1), GitVersion.parse("git version 2.45.1.windows.1"))
        assertEquals("2.40.0", GitVersion.parse("git version 2.40")!!.display)
        listOf("", "version 2.40.0", "git version two", "git version 2.40.0/../../etc").forEach { assertNull(GitVersion.parse(it), it) }
    }

    @Test fun `startup detection reports installed missing old and unrecognizable executables`(): Unit = GitTestRepositories().use { f ->
        val installed = GitRuntime.detect()
        assertTrue(installed is GitAvailability.Available)
        assertTrue(installed.version >= GitVersion.MINIMUM)
        val missing = GitRuntime.detect(listOf(f.root.resolve("absent/git"), Path.of("relative/git")))
        assertEquals("GIT_NOT_FOUND", (missing as GitAvailability.Unavailable).reasonCode)
        assertNull(missing.version)
        val old = GitRuntime.detect(listOf(fakeGit(f.root.resolve("old"), "echo 'git version 2.20.1'")))
        assertEquals("GIT_VERSION_UNSUPPORTED", (old as GitAvailability.Unavailable).reasonCode)
        assertEquals("2.20.1", old.version!!.display)
        assertFalse(old.message.contains(f.root.toString()))
        val garbage = GitRuntime.detect(listOf(fakeGit(f.root.resolve("garbage"), "echo PRIVATE_CANARY; exit 0")))
        assertEquals("GIT_PROBE_FAILED", (garbage as GitAvailability.Unavailable).reasonCode)
        assertFalse(garbage.message.contains("PRIVATE_CANARY"))
    }

    @Test fun `argv is passed without a shell and the child environment is fixed`(): Unit = GitTestRepositories().use { f ->
        val marker = f.root.resolve("shell-ran")
        val echo = fakeGit(f.root.resolve("echo"), "for argument in \"\$@\"; do printf '[%s]\\n' \"\$argument\"; done; env | LC_ALL=C sort")
        val runner = GitCommandRunner(echo, f.environment)
        val hostile = "\$(touch '$marker') ; touch '$marker' | `id`"
        val output = runner.run(GitInvocation("check-ref-format", listOf("refs/heads/a b", hostile))).text
        assertFalse(marker.exists())
        assertTrue(output.contains("[$hostile]") && output.contains("[refs/heads/a b]"))
        assertTrue(output.contains("[core.hooksPath=${f.environment.hooks}]") && output.contains("[protocol.allow=never]"))
        assertTrue(output.contains("[core.fsmonitor=false]") && output.contains("[credential.helper=]"))
        val names = output.lineSequence().filter { !it.startsWith("[") && it.contains('=') }.map { it.substringBefore('=') }.toSet()
        // A few shells add PWD/SHLVL/_ themselves; nothing comes from the JVM's environment.
        assertEquals(f.environment.variables(echo).keys, names - setOf("PWD", "SHLVL", "_", "OLDPWD"))
        assertTrue(output.contains("GIT_CONFIG_GLOBAL=${f.environment.emptyFile}") && output.contains("GIT_CONFIG_NOSYSTEM=1"))
        assertTrue(output.contains("HOME=${f.environment.home}") && output.contains("GIT_TERMINAL_PROMPT=0"))
        assertFailsWith<IllegalArgumentException> { GitInvocation("-c") }
        assertFailsWith<IllegalArgumentException> { GitInvocation("--git-dir=/") }
        assertFailsWith<IllegalArgumentException> { GitInvocation("push") }
        assertFailsWith<IllegalArgumentException> { GitInvocation("status", listOf("a\u0000b")) }
        assertFailsWith<IllegalArgumentException> { GitInvocation("status", List(257) { "x" }) }
        assertFailsWith<IllegalArgumentException> { GitInvocation("status", gitDir = Path.of("relative")) }
        assertFailsWith<IllegalArgumentException> { GitInvocation("status", workTree = f.root) }
    }

    @Test fun `time and output bounds terminate the child`(): Unit = GitTestRepositories().use { f ->
        val slow = GitCommandRunner(fakeGit(f.root.resolve("slow"), "sleep 30"), f.environment)
        val started = System.nanoTime()
        val timeout = assertFailsWith<GitCommandException> {
            slow.run(GitInvocation("status", limits = GitExecutionLimits(Duration.ofMillis(500))))
        }
        assertEquals(GitCommandException.Kind.TIMED_OUT, timeout.kind)
        assertTrue(Duration.ofNanos(System.nanoTime() - started) < Duration.ofSeconds(10))
        val loud = GitCommandRunner(fakeGit(f.root.resolve("loud"), "head -c 4000000 /dev/zero"), f.environment)
        assertEquals(GitCommandException.Kind.OUTPUT_LIMIT, assertFailsWith<GitCommandException> {
            loud.run(GitInvocation("status", limits = GitExecutionLimits(maxStdoutBytes = 4096)))
        }.kind)
        val truncated = loud.run(GitInvocation("status", truncateStdout = true, limits = GitExecutionLimits(maxStdoutBytes = 4096)))
        assertTrue(truncated.stdoutTruncated); assertEquals(4096, truncated.stdout.size)
        // A child that exits immediately after slightly overrunning the bound races its own reader;
        // truncation must still be reported, never an output-limit failure.
        val brief = GitCommandRunner(fakeGit(f.root.resolve("brief"), "head -c 5000 /dev/zero"), f.environment)
        repeat(200) {
            val result = brief.run(GitInvocation("status", truncateStdout = true, limits = GitExecutionLimits(maxStdoutBytes = 4096)))
            assertTrue(result.stdoutTruncated); assertEquals(4096, result.stdout.size)
        }
        val noisy = GitCommandRunner(fakeGit(f.root.resolve("noisy"), "head -c 4000000 /dev/zero >&2"), f.environment)
        assertEquals(GitCommandException.Kind.OUTPUT_LIMIT, assertFailsWith<GitCommandException> {
            noisy.run(GitInvocation("status", limits = GitExecutionLimits(maxStderrBytes = 4096)))
        }.kind)
        assertEquals(GitCommandException.Kind.OUTPUT_LIMIT, assertFailsWith<GitCommandException> {
            noisy.run(GitInvocation("status", truncateStdout = true, limits = GitExecutionLimits(maxStderrBytes = 4096)))
        }.kind)
        val failing = GitCommandRunner(fakeGit(f.root.resolve("failing"), "echo PRIVATE_CANARY >&2; exit 3"), f.environment)
        val failure = assertFailsWith<GitCommandException> { failing.run(GitInvocation("status")) }
        assertEquals(GitCommandException.Kind.FAILED, failure.kind); assertEquals(3, failure.exitCode)
        assertFalse(failure.message!!.contains("PRIVATE_CANARY"))
    }

    private fun childStopped(pid: Long): Boolean {
        val stat = Path.of("/proc", pid.toString(), "stat")
        return try {
            val text = Files.readString(stat)
            text[text.lastIndexOf(") ") + 2] in setOf('Z', 'X', 'x')
        } catch (_: java.io.IOException) {
            // /proc can vanish after open, yielding ESRCH from read rather than ENOENT.
            !ProcessHandle.of(pid).map { it.isAlive }.orElse(false)
        }
    }

    private fun requireChildStopped(pidFile: Path) {
        val pid = Files.readString(pidFile).trim().toLong()
        try {
            val deadline = System.nanoTime() + Duration.ofSeconds(2).toNanos()
            while (!childStopped(pid) && System.nanoTime() < deadline) Thread.sleep(5)
            assertTrue(childStopped(pid), "descendant $pid is still executing after runner returned")
        } finally {
            // A regression must not leave the test's own 30-second sleeper behind.
            if (!childStopped(pid)) ProcessHandle.of(pid).ifPresent { it.destroyForcibly() }
        }
    }

    @Test fun `parent exits first with inherited or closed output pipes leaves no executing child`(): Unit = GitTestRepositories().use { f ->
        for (redirect in listOf("", ">/dev/null 2>&1")) repeat(10) { index ->
            val pid = f.root.resolve("orphan-${redirect.length}-$index.pid")
            val runner = GitCommandRunner(fakeGit(f.root.resolve("orphan-${redirect.length}-$index"),
                "sleep 30 $redirect &\necho \$! > '$pid'\nexit 0"), f.environment)
            val started = System.nanoTime()
            try {
                assertEquals(0, runner.run(GitInvocation("status", limits = GitExecutionLimits(Duration.ofMillis(500)))).exitCode)
                assertTrue(Duration.ofNanos(System.nanoTime() - started) < Duration.ofSeconds(2))
            } finally {
                requireChildStopped(pid)
            }
        }
    }

    @Test fun `timeout output failure and interruption clean the owned group`(): Unit = GitTestRepositories().use { f ->
        data class Case(val name: String, val body: String, val limits: GitExecutionLimits, val kind: GitCommandException.Kind)
        for ((name, body, limits, kind) in listOf(
            Case("timeout", "wait", GitExecutionLimits(Duration.ofMillis(500)), GitCommandException.Kind.TIMED_OUT),
            Case("output", "head -c 4000000 /dev/zero; wait", GitExecutionLimits(maxStdoutBytes = 4096), GitCommandException.Kind.OUTPUT_LIMIT),
            Case("stderr", "head -c 4000000 /dev/zero >&2; wait", GitExecutionLimits(maxStderrBytes = 4096), GitCommandException.Kind.OUTPUT_LIMIT),
        )) {
            val pid = f.root.resolve("$name.pid")
            val runner = GitCommandRunner(fakeGit(f.root.resolve(name), "sleep 30 &\necho \$! > '$pid'\n$body"), f.environment)
            try {
                assertEquals(kind, assertFailsWith<GitCommandException> {
                    runner.run(GitInvocation("status", limits = limits))
                }.kind)
            } finally { requireChildStopped(pid) }
        }
        for (truncate in listOf(false, true)) {
            val pid = f.root.resolve("terminal-$truncate.pid")
            val body = if (truncate) "head -c 4000000 /dev/zero; wait" else "exit 3"
            val runner = GitCommandRunner(fakeGit(f.root.resolve("terminal-$truncate"),
                "sleep 30 &\necho \$! > '$pid'\n$body"), f.environment)
            try {
                if (truncate) {
                    val result = runner.run(GitInvocation("status", truncateStdout = true,
                        limits = GitExecutionLimits(maxStdoutBytes = 4096)))
                    assertTrue(result.stdoutTruncated)
                    assertEquals(4096, result.stdout.size)
                } else {
                    val failure = assertFailsWith<GitCommandException> { runner.run(GitInvocation("status")) }
                    assertEquals(GitCommandException.Kind.FAILED, failure.kind)
                    assertEquals(3, failure.exitCode)
                }
            } finally { requireChildStopped(pid) }
        }
        val pid = f.root.resolve("interrupted.pid")
        val runner = GitCommandRunner(fakeGit(f.root.resolve("interrupted"), "sleep 30 &\necho \$! > '$pid'\nwait"), f.environment)
        val failure = java.util.concurrent.atomic.AtomicReference<Throwable?>()
        val interrupted = java.util.concurrent.atomic.AtomicBoolean()
        val thread = Thread.ofPlatform().start {
            try { runner.run(GitInvocation("status")) } catch (caught: Throwable) { failure.set(caught) }
            interrupted.set(Thread.currentThread().isInterrupted)
        }
        try {
            val deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos()
            while ((!Files.exists(pid) || Files.size(pid) == 0L) && System.nanoTime() < deadline) Thread.sleep(5)
            thread.interrupt()
            thread.join(7000)
            assertFalse(thread.isAlive)
            assertEquals(GitCommandException.Kind.INTERRUPTED, (failure.get() as GitCommandException).kind)
            assertTrue(interrupted.get())
        } finally {
            thread.interrupt()
            requireChildStopped(pid)
        }
    }

    @Test fun `branch names are validated by local syntax and check-ref-format`(): Unit = GitTestRepositories().use { f ->
        listOf("main", "trunk", "feature/one", "release-1.2", "功能", "x_y").forEach {
            assertEquals(it, GitRefNames.requireBranchName(f.runner, it))
        }
        listOf("", "-x", "--upload-pack=touch", "a..b", "a b", "x.lock", "a/.hidden", "@{u}", "HEAD", "@", "a\u0001", "a~1", "a^",
            "a:b", "a?", "a*", "a[", "a\\b", "/a", "a/", "a//b", "a.", "x".repeat(201)).forEach { name ->
            assertFailsWith<IllegalArgumentException>(name) { GitRefNames.requireBranchName(f.runner, name) }
        }
    }

    @Test fun `object IDs are opaque full-length values for their declared format`() {
        val sha1 = "a".repeat(40); val sha256 = "b".repeat(64)
        assertEquals(sha1, GitObjectFormat.SHA1.requireObjectId(sha1))
        assertEquals(sha256, GitObjectFormat.SHA256.requireObjectId(sha256))
        assertNull(GitObjectFormat.SHA1.objectIdOrNull(sha256)); assertNull(GitObjectFormat.SHA256.objectIdOrNull(sha1))
        assertNull(GitObjectFormat.SHA1.objectIdOrNull("abcdef1")); assertNull(GitObjectFormat.SHA1.objectIdOrNull("A".repeat(40)))
        assertNull(GitObjectFormat.UNKNOWN.objectIdOrNull(sha1))
        assertEquals(GitObjectFormat.UNKNOWN, GitObjectFormat.fromGit("sha512"))
        assertEquals(GitObjectFormat.SHA256, GitObjectFormat.fromGit("sha256\n"))
    }

    @Test fun `source-only tracking policy excludes job state and keeps intended sources`(): Unit = GitTestRepositories().use { f ->
        val (gitDir, workTree) = f.managed("policy")
        assertEquals(GitTrackingPolicy.excludeFile(), Files.readString(gitDir.resolve("info/exclude")))
        val kept = listOf("src/main.c", "src/core/state.c", "src/tmp/helper.c", "src/sessions/table.c", "include/module.h",
            "CMakeLists.txt", "Makefile", "README.md", "source_tree_manifest.json", "src/reports/format.c", "cmake/toolchain.cmake",
            "src/build/rules.c", "docs/design.md")
        val excluded = listOf("input.elf", "build/main.o", "src/main.o", "lib/libx.a", "lib/libx.so.1", "out/app",
            ".env", ".env.local", "keys/id_ed25519", "certs/server.pem", ".git-credentials", "job.json", "workflow-state.json",
            "state/calls.sqlite", "transcripts/session.txt", "sessions/agent.json", "progress.jsonl", "reports/run.json",
            "evidence/case.json", "logs/build.log", "CMakeFiles/rules.make", "CMakeCache.txt", "compile_commands.json",
            "cmake-build-debug/app", "build.ninja", "tmp/scratch.c", "src/main.d")
        (kept + excluded).forEach { path ->
            Files.createDirectories(workTree.resolve(path).parent ?: workTree)
            Files.writeString(workTree.resolve(path), "fixture\n")
        }
        val ignored = f.runner.run(GitInvocation("check-ignore", listOf("--") + kept + excluded, gitDir = gitDir, workTree = workTree,
            allowedExitCodes = setOf(0, 1))).text.lineSequence().filter { it.isNotEmpty() }.toSet()
        assertEquals(excluded.toSet(), ignored)
        assertTrue(GitTrackingPolicy.CATEGORIES.map { it.id }.containsAll(listOf("original-binaries", "credentials",
            "job-runtime-state", "private-transcripts", "native-build-output", "transient-evidence")))
    }

    @Test fun `pending workflow state and all database sidecars remain excluded despite negations`(): Unit = GitTestRepositories().use { f ->
        val (gitDir, workTree) = f.managed("runtime-sidecars")
        val excluded = listOf("workflow-state.pending.json", "state/workflow-state.pending.json") +
            listOf("sqlite", "sqlite3", "db").flatMap { extension ->
                listOf("", "-journal", "-wal", "-shm").map { sidecar -> "state/calls.$extension$sidecar" }
            }
        val retained = listOf("src/workflow-state.pending.json.c", "src/calls.sqlite-wal.c", "include/calls.db-shm.h",
            "source_tree_manifest.json", "CMakeLists.txt", "docs/database.md")
        Files.writeString(workTree.resolve(".gitignore"), excluded.joinToString("") { "!/$it\n" })
        (excluded + retained).forEach { path ->
            Files.createDirectories(workTree.resolve(path).parent)
            Files.writeString(workTree.resolve(path), "fixture\n")
        }
        // Demonstrate that the managed repository's ignore result is not the admission decision.
        assertEquals(1, f.runner.run(GitInvocation("check-ignore", listOf("--no-index", "--") + excluded,
            gitDir = gitDir, workTree = workTree, allowedExitCodes = setOf(0, 1))).exitCode)
        assertEquals(excluded.toSet(), GitTrackingPolicy.excluded(f.runner, excluded + retained))
        // The presentation rules still cover the same categories when not overridden in-tree.
        Files.delete(workTree.resolve(".gitignore"))
        assertEquals(excluded.toSet(), f.runner.run(GitInvocation("check-ignore", listOf("--") + excluded + retained,
            gitDir = gitDir, workTree = workTree)).text.lineSequence().filter { it.isNotEmpty() }.toSet())
    }

    @Test fun `repository ignore files cannot re-include policy exclusions`(): Unit = GitTestRepositories().use { f ->
        val (gitDir, workTree) = f.managed("negated")
        Files.writeString(workTree.resolve(".gitignore"), "!secret.key\n!*.elf\n!/build/\n")
        Files.writeString(workTree.resolve("secret.key"), "PRIVATE")
        Files.writeString(workTree.resolve("input.elf"), "ELF")
        Files.writeString(workTree.resolve("main.c"), "int main;\n")
        // Git itself lets the in-tree negation win over info/exclude ...
        val untracked = f.runner.run(GitInvocation("status", listOf("--porcelain=v1", "-z", "--untracked-files=all"),
            gitDir = gitDir, workTree = workTree)).text
        assertTrue(untracked.contains("?? secret.key"))
        // ... so the policy decision is made where only the policy applies.
        val paths = listOf("secret.key", "input.elf", "build/main.o", "src/deep/.env", "main.c", ".gitignore", "src/build/rules.c")
        assertEquals(setOf("secret.key", "input.elf", "build/main.o", "src/deep/.env"), GitTrackingPolicy.excluded(f.runner, paths))
        assertEquals(setOf("-rf.key", "new\nline.key", "ünï.pem"),
            GitTrackingPolicy.excluded(f.runner, (1..450).map { "src/file$it.c" } + listOf("-rf.key", "new\nline.key", "ünï.pem", "quote\".c")))
    }

    @Test fun `system and global configuration never reach a managed repository command`(): Unit = GitTestRepositories().use { f ->
        val (gitDir, _) = f.managed("scopes")
        val scopes = f.runner.run(GitInvocation("config", listOf("--list", "--show-scope"), gitDir = gitDir)).text
            .lineSequence().filter { it.isNotEmpty() }.map { it.substringBefore('\t') }.toSet()
        assertEquals(setOf("command", "local"), scopes)
        assertEquals(0L, Files.size(f.environment.emptyFile))
        assertTrue(Files.list(f.environment.hooks).use { it.count() } == 0L)
        // The init template directory is empty, so no sample hooks or info files are copied in.
        assertFalse(gitDir.resolve("hooks").exists() && Files.list(gitDir.resolve("hooks")).use { it.count() } > 0)
    }

    @Test fun `inspection reports unborn attached dirty detached and sha256 states without assuming main`(): Unit = GitTestRepositories().use { f ->
        val (gitDir, workTree) = f.managed("states", branch = "trunk")
        val unborn = GitRepositoryInspector.inspect(f.runner, gitDir, workTree)
        assertEquals(GitHeadObservation(GitHeadState.UNBORN, "refs/heads/trunk", null), unborn.head)
        assertFalse(unborn.dirty); assertTrue(unborn.refs.isEmpty()); assertEquals(GitObjectFormat.SHA1, unborn.objectFormat)
        Files.writeString(workTree.resolve("main.c"), "int main(void) { return 0; }\n")
        val untracked = GitRepositoryInspector.inspect(f.runner, gitDir, workTree)
        assertTrue(untracked.dirty); assertNotEquals(unborn.statusDigest, untracked.statusDigest)
        val commit = f.commitAll(gitDir, workTree, "fixture")
        val clean = GitRepositoryInspector.inspect(f.runner, gitDir, workTree)
        assertEquals(GitHeadObservation(GitHeadState.ATTACHED, "refs/heads/trunk", commit), clean.head)
        assertEquals(listOf(GitRefObservation("refs/heads/trunk", commit)), clean.refs)
        assertFalse(clean.dirty)
        Files.writeString(workTree.resolve("main.c"), "int main(void) { return 1; }\n")
        assertTrue(GitRepositoryInspector.inspect(f.runner, gitDir, workTree).dirty)
        f.git("--git-dir=$gitDir", "update-ref", "--no-deref", "HEAD", commit)
        val detached = GitRepositoryInspector.inspect(f.runner, gitDir, workTree)
        assertEquals(GitHeadObservation(GitHeadState.DETACHED, null, commit), detached.head)

        val (wideDir, wideTree) = f.managed("wide", branch = "default", format = "sha256")
        Files.writeString(wideTree.resolve("a.c"), "/* sha256 */\n")
        val wideCommit = f.commitAll(wideDir, wideTree, "wide")
        val wide = GitRepositoryInspector.inspect(f.runner, wideDir, wideTree)
        assertEquals(GitObjectFormat.SHA256, wide.objectFormat); assertEquals(64, wide.head.objectId!!.length)
        assertEquals(wideCommit, wide.head.objectId)
    }

    @Test fun `symbolic HEAD must name a branch rather than a tag or other namespace`(): Unit = GitTestRepositories().use { f ->
        val (gitDir, workTree) = f.managed("head-namespace")
        Files.writeString(workTree.resolve("main.c"), "int main;\n")
        val commit = f.commitAll(gitDir, workTree, "fixture")
        f.git("--git-dir=$gitDir", "update-ref", "refs/tags/odd", commit)
        for (ref in listOf("refs/tags/odd", "refs/tags/missing", "refs/custom/missing")) {
            f.git("--git-dir=$gitDir", "symbolic-ref", "HEAD", ref)
            assertEquals("REPOSITORY_UNSUPPORTED", assertFailsWith<GitRepositoryException>(ref) {
                GitRepositoryInspector.inspect(f.runner, gitDir, workTree)
            }.code)
        }
    }

    @Test fun `bounded refs always retain the attached HEAD without duplicates`(): Unit = GitTestRepositories().use { f ->
        val (gitDir, workTree) = f.managed("many-refs")
        Files.writeString(workTree.resolve("main.c"), "int main;\n")
        val commit = f.commitAll(gitDir, workTree, "fixture")
        repeat(GitRepositoryInspector.MAX_REFS - 1) { index ->
            f.git("--git-dir=$gitDir", "update-ref", "refs/heads/a%03d".format(index), commit)
        }
        val full = GitRepositoryInspector.inspect(f.runner, gitDir, workTree)
        assertEquals(GitRepositoryInspector.MAX_REFS, full.refs.size)
        assertFalse(full.refsTruncated)
        assertTrue(GitRefObservation("refs/heads/trunk", commit) in full.refs)
        repeat(8) { index ->
            f.git("--git-dir=$gitDir", "update-ref", "refs/heads/a%03d".format(GitRepositoryInspector.MAX_REFS - 1 + index), commit)
        }
        val bounded = GitRepositoryInspector.inspect(f.runner, gitDir, workTree)
        assertTrue(bounded.refsTruncated)
        assertEquals(GitRepositoryInspector.MAX_REFS, bounded.refs.size)
        assertEquals(1, bounded.refs.count { it == GitRefObservation("refs/heads/trunk", commit) })
        f.git("--git-dir=$gitDir", "symbolic-ref", "HEAD", "refs/heads/a000")
        val earlyHead = GitRepositoryInspector.inspect(f.runner, gitDir, workTree)
        assertTrue(earlyHead.refsTruncated)
        assertEquals(GitRepositoryInspector.MAX_REFS, earlyHead.refs.size)
        assertEquals(1, earlyHead.refs.count { it.name == "refs/heads/a000" && it.objectId == commit })
    }

    @Test fun `status fingerprint is display only and not dirty source identity`(): Unit = GitTestRepositories().use { f ->
        val (gitDir, workTree) = f.managed("status-display")
        val source = workTree.resolve("main.c")
        Files.writeString(source, "int one;\n")
        val untracked = GitRepositoryInspector.inspect(f.runner, gitDir, workTree)
        val firstBytes = Files.readAllBytes(source)
        Files.writeString(source, "int two_different;\n")
        val editedUntracked = GitRepositoryInspector.inspect(f.runner, gitDir, workTree)
        assertFalse(firstBytes.contentEquals(Files.readAllBytes(source)))
        assertTrue(untracked.dirty && editedUntracked.dirty)
        assertEquals(untracked.statusDigest, editedUntracked.statusDigest)
        f.commitAll(gitDir, workTree, "fixture")
        Files.writeString(source, "int tracked_dirty;\n")
        val modified = GitRepositoryInspector.inspect(f.runner, gitDir, workTree)
        val modifiedBytes = Files.readAllBytes(source)
        Files.writeString(source, "int tracked_dirty_again;\n")
        val editedModified = GitRepositoryInspector.inspect(f.runner, gitDir, workTree)
        assertFalse(modifiedBytes.contentEquals(Files.readAllBytes(source)))
        assertTrue(modified.dirty && editedModified.dirty)
        assertEquals(modified.statusDigest, editedModified.statusDigest)
    }

    @Test fun `linked roots ancestors worktrees and nested repository metadata are refused`(): Unit = GitTestRepositories().use { f ->
        val (gitDir, workTree) = f.managed("physical")
        val linkedRoot = Files.createSymbolicLink(f.root.resolve("linked-root.git"), gitDir)
        val linkedParent = Files.createSymbolicLink(f.root.resolve("linked-parent"), f.root)
        val linkedTree = Files.createSymbolicLink(f.root.resolve("linked-worktree"), workTree)
        for ((directory, tree) in listOf(linkedRoot to workTree, linkedParent.resolve(gitDir.fileName) to workTree, gitDir to linkedTree)) {
            assertEquals("REPOSITORY_UNSUPPORTED", assertFailsWith<GitRepositoryException> {
                GitRepositoryInspector.inspect(f.runner, directory, tree)
            }.code)
        }
        assertEquals("REPOSITORY_UNSUPPORTED", assertFailsWith<GitRepositoryException> {
            GitManagedLayout.prepare(linkedRoot)
        }.code)
        for (component in listOf("info", "objects", "refs", "refs/heads", "HEAD", "config", "info/attributes")) {
            val (directory, tree) = f.managed("linked-${component.replace('/', '-')}")
            val entry = directory.resolve(component)
            val target = f.root.resolve("target-${component.replace('/', '-')}")
            Files.move(entry, target)
            Files.createSymbolicLink(entry, target)
            assertEquals("REPOSITORY_UNSUPPORTED", assertFailsWith<GitRepositoryException>(component) {
                GitRepositoryInspector.inspect(f.runner, directory, tree)
            }.code)
        }
        // Links deeper than fixed layout components must not escape the check either.
        Files.createSymbolicLink(gitDir.resolve("refs/heads/linked"), f.root)
        assertEquals("REPOSITORY_UNSUPPORTED", assertFailsWith<GitRepositoryException> {
            GitRepositoryInspector.inspect(f.runner, gitDir, workTree)
        }.code)
    }

    @Test fun `missing corrupt and unreviewed repositories have distinct outcomes`(): Unit = GitTestRepositories().use { f ->
        val missing = assertFailsWith<GitRepositoryException> {
            GitRepositoryInspector.inspect(f.runner, f.root.resolve("absent.git"), f.root)
        }
        assertEquals("REPOSITORY_UNSUPPORTED", missing.code)
        val (gitDir, workTree) = f.managed("corrupt")
        Files.createDirectories(gitDir.resolve("refs/heads"))
        Files.writeString(gitDir.resolve("refs/heads/trunk"), "1".repeat(40) + "\n")
        assertEquals("REPOSITORY_CORRUPT", assertFailsWith<GitRepositoryException> {
            GitRepositoryInspector.inspect(f.runner, gitDir, workTree)
        }.code)
        val (linked, linkedTree) = f.managed("linked")
        Files.writeString(linked.resolve("objects/info/alternates"), f.root.toString() + "\n")
        assertEquals("REPOSITORY_UNSUPPORTED", assertFailsWith<GitRepositoryException> {
            GitRepositoryInspector.inspect(f.runner, linked, linkedTree)
        }.code)
        for (setting in listOf("filter.evil.smudge", "core.fsmonitor", "include.path", "diff.external", "core.worktree", "alias.st")) {
            val (configured, configuredTree) = f.managed("configured-${setting.replace('.', '-')}")
            val marker = f.root.resolve("$setting-ran")
            f.git("config", "--file", configured.resolve("config").toString(), setting, f.tripwire("$setting.sh", marker).toString())
            assertEquals("REPOSITORY_CONFIG_UNTRUSTED", assertFailsWith<GitRepositoryException>(setting) {
                GitRepositoryInspector.inspect(f.runner, configured, configuredTree)
            }.code)
            assertFalse(marker.exists())
        }
    }

    @Test fun `hooks attribute filters submodules and fsmonitor in repository content stay inert`(): Unit = GitTestRepositories().use { f ->
        val marker = f.root.resolve("tripwire-ran")
        val (gitDir, workTree) = f.managed("inert")
        // Driver attributes have no driver; built-in conversions (EOL, ident, encoding) are unset by
        // the server's highest-precedence info/attributes, so checkout keeps the exact blob bytes.
        Files.writeString(workTree.resolve(".gitattributes"),
            "* filter=evil diff=evil merge=evil text eol=crlf\nid.c ident\nwide.c working-tree-encoding=UTF-16LE\n")
        Files.write(workTree.resolve("lf.c"), "int x;\n".toByteArray())
        Files.write(workTree.resolve("id.c"), "/* \$Id\$ */\n".toByteArray())
        Files.write(workTree.resolve("wide.c"), "abc\n".toByteArray())
        Files.writeString(workTree.resolve(".gitmodules"), "[submodule \"x\"]\n\tpath = vendor\n\turl = ${f.root.resolve("elsewhere")}\n")
        Files.write(workTree.resolve("source.c"), "int value = 1;\r\n".toByteArray())
        val commit = f.commitAll(gitDir, workTree, "attributes")
        // Hooks are present in the repository and in an imported-style hooksPath, and fsmonitor
        // points at a tripwire. Command-line configuration outranks the repository's own values.
        Files.createDirectories(gitDir.resolve("hooks"))
        for (hook in listOf("post-checkout", "post-index-change", "reference-transaction", "pre-auto-gc")) {
            Files.copy(f.tripwire("$hook.sh", marker), gitDir.resolve("hooks/$hook"))
        }
        val tree = Files.createDirectories(f.root.resolve("checkout tree"))
        f.runner.run(GitInvocation("read-tree", listOf("--reset", "-u", commit), gitDir = gitDir, workTree = tree))
        assertContentEquals("int value = 1;\r\n".toByteArray(), Files.readAllBytes(tree.resolve("source.c")))
        assertContentEquals("int x;\n".toByteArray(), Files.readAllBytes(tree.resolve("lf.c")))
        assertContentEquals("/* \$Id\$ */\n".toByteArray(), Files.readAllBytes(tree.resolve("id.c")))
        assertContentEquals("abc\n".toByteArray(), Files.readAllBytes(tree.resolve("wide.c")))
        assertFalse(tree.resolve("vendor").resolve(".git").exists())
        GitRepositoryInspector.inspect(f.runner, gitDir, tree)
        // Bypass the audit to show the command-line values alone neutralize these repository keys.
        val config = gitDir.resolve("config").toString()
        f.git("config", "--file", config, "core.fsmonitor", f.tripwire("fsmonitor.sh", marker).toString())
        f.git("config", "--file", config, "core.hooksPath", gitDir.resolve("hooks").toString())
        Files.writeString(tree.resolve("source.c"), "int value = 2;\n")
        f.runner.run(GitInvocation("status", listOf("--porcelain=v1", "-z"), gitDir = gitDir, workTree = tree))
        f.runner.run(GitInvocation("read-tree", listOf("--reset", "-u", commit), gitDir = gitDir, workTree = tree))
        assertFalse(marker.exists())
        // A managed repository whose attribute neutralization was changed is refused before Git runs.
        val (tampered, tamperedTree) = f.managed("tampered")
        Files.writeString(tampered.resolve("info/attributes"), "* text eol=crlf\n")
        assertEquals("REPOSITORY_CONFIG_UNTRUSTED", assertFailsWith<GitRepositoryException> {
            GitRepositoryInspector.inspect(f.runner, tampered, tamperedTree)
        }.code)
    }
}
