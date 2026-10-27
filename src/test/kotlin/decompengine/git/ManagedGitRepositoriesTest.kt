package decompengine.git

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.io.path.exists
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ManagedGitRepositoriesTest {
    private val jobId = "0123456789abcdef0123456789abcdef"

    /** A job directory with one recorded source snapshot under its run reports, like the job store layout. */
    private inner class Fixture(
        val repositories: GitTestRepositories = GitTestRepositories(),
        private val importRoot: Path? = null,
    ) : AutoCloseable {
        val store: Path = Files.createDirectories(repositories.root.resolve("store"))
        val snapshot: Path = Files.createDirectories(store.resolve(jobId).resolve("reports/runs/run_1/source-tree"))
        val crashes = mutableSetOf<GitOperationCrashPoint>()
        private val opened = mutableListOf<ManagedGitRepositories>()
        val resolver = GitSourceSnapshotResolver { job, run, revision ->
            if (job != jobId || run != "run_1" || revision != "revision_1") {
                throw ManagedGitException("SOURCE_REVISION_UNAVAILABLE", "The selected source snapshot is unavailable.")
            }
            GitSourceSnapshot(snapshot, run, revision, "a".repeat(64), commitments)
        }

        init {
            write("CMakeLists.txt", "cmake_minimum_required(VERSION 3.20)\nproject(fixture C)\n")
            write("src/main file.c", "int main(void) { return 0; }\r\n")
            write("src/ünïcode/módulo.c", "/* módulo */\n")
            write("include/fixture.h", "#pragma once\n")
            write("input.elf", "\u007fELF not a real binary")
            write("build/main.o", "native output")
            write(".env", "TOKEN=fixture-only")
            write("source_tree_manifest.json", "{}\n")
            Files.setPosixFilePermissions(snapshot.resolve("CMakeLists.txt"), PosixFilePermissions.fromString("rwxr-xr-x"))
        }

        /** The candidate's recorded build inputs, captured once like a completed attempt's commitments. */
        val commitments: Map<String, GitSourceCommitment> = listOf("CMakeLists.txt", "src/main file.c", "src/ünïcode/módulo.c",
            "include/fixture.h").associateWith { path ->
            GitSourceCommitment(GitSourceCopy.digestOf(snapshot.resolve(path)), Files.size(snapshot.resolve(path)))
        }

        fun write(path: String, text: String) {
            val file = snapshot.resolve(path)
            Files.createDirectories(file.parent)
            Files.write(file, text.toByteArray())
        }

        fun open(policy: GitRepositoryPolicy = GitRepositoryPolicy(defaultBranch = "trunk"),
            availability: GitAvailability = GitRuntime.detect(), limits: GitCheckoutLimits = GitCheckoutLimits()): ManagedGitRepositories =
            ManagedGitRepositories(store, availability, resolver, importRoot, policy, crash = { point ->
                if (point in crashes) throw SimulatedGitCrash()
            }, importLimits = limits).also(opened::add)

        fun tree(root: Path): Map<String, List<Byte>> = Files.walk(root).use { paths ->
            paths.filter { Files.isRegularFile(it, NOFOLLOW_LINKS) }.toList()
                .associate { root.relativize(it).toString() to Files.readAllBytes(it).toList() }
        }

        fun repositoryDirectory(repositoryId: String): Path = store.resolve(jobId).resolve("git/repositories").resolve(repositoryId)

        override fun close() { opened.forEach { it.close() }; repositories.close() }
    }

    private fun ManagedGitRepositories.settle(admission: GitOperationAdmission): GitOperationRecord {
        assertTrue(awaitIdle(60_000))
        return operation(jobId, admission.operation.repositoryId, admission.operation.operationId)
    }

    @Test fun `initialization copies source bytes exactly, applies policy and creates no commit`(): Unit = Fixture().use { f ->
        val before = f.tree(f.snapshot)
        val service = f.open()
        val admission = service.request(jobId, GitRepositoryRequest.Init("run_1", "revision_1", null), "init_request_key_0001")
        assertEquals(GitOperationState.QUEUED, admission.operation.state)
        val completed = service.settle(admission)
        assertEquals(GitOperationState.COMPLETED, completed.state, completed.message)
        assertNull(completed.resultObjectId)
        assertEquals(before, f.tree(f.snapshot))
        val view = service.workspace(jobId, completed.repositoryId)
        assertEquals(GitHeadObservation(GitHeadState.UNBORN, "refs/heads/trunk", null), view.observation.head)
        assertTrue(view.observation.refs.isEmpty()); assertTrue(view.observation.dirty)
        assertEquals("revision_1", view.record.candidateRevisionId); assertEquals("initialized", view.record.origin)
        val directory = f.repositoryDirectory(completed.repositoryId)
        val workTree = directory.resolve("worktree")
        // Every copied byte matches, the build output root is not copied and no file was added.
        assertEquals(before - "build/main.o", f.tree(workTree))
        assertTrue(Files.isExecutable(workTree.resolve("CMakeLists.txt")))
        assertFalse(workTree.resolve(".gitignore").exists()); assertFalse(workTree.resolve(".git").exists())
        val gitDir = directory.resolve("repository.git")
        assertEquals(GitTrackingPolicy.excludeFile(), Files.readString(gitDir.resolve("info/exclude")))
        val config = GitConfigurationAudit.read(f.repositories.runner, gitDir.resolve("config")).toMap()
        assertEquals("Decomp Workbench", config["user.name"]); assertEquals("true", config["core.bare"])
        // Policy-excluded files stay untracked and ignored; intended sources are visible as untracked.
        val status = f.repositories.runner.run(GitInvocation("status", listOf("--porcelain=v1", "-z", "--untracked-files=all", "--ignored"),
            gitDir = gitDir, workTree = workTree)).text.split('\u0000').filter { it.isNotEmpty() }.toSet()
        assertTrue("?? src/main file.c" in status && "?? CMakeLists.txt" in status && "?? source_tree_manifest.json" in status)
        assertTrue("!! input.elf" in status && "!! .env" in status)
        assertFalse(f.repositories.git("--git-dir=$gitDir", "rev-list", "--all").isNotBlank())
        // Replay returns the same operation; a second request cannot replace the repository.
        val replay = service.request(jobId, GitRepositoryRequest.Init("run_1", "revision_1", null), "init_request_key_0001")
        assertTrue(replay.replayed); assertEquals(completed, replay.operation)
        assertEquals("IDEMPOTENCY_CONFLICT", assertFailsWith<ManagedGitException> {
            service.request(jobId, GitRepositoryRequest.Init("run_1", "revision_1", "other"), "init_request_key_0001")
        }.code)
        assertEquals("REPOSITORY_EXISTS", assertFailsWith<ManagedGitException> {
            service.request(jobId, GitRepositoryRequest.Init("run_1", "revision_1", null), "init_request_key_0002")
        }.code)
    }

    @Test fun `retention protects commits without remotes and detached or tag-only unpushed work`(): Unit = Fixture().use { f ->
        val service = f.open()
        val completed = service.settle(service.request(jobId, GitRepositoryRequest.Init("run_1", "revision_1", null), "retention_request_0001"))
        val directory = f.repositoryDirectory(completed.repositoryId)
        val gitDir = directory.resolve("repository.git")
        val workTree = directory.resolve("worktree")
        fun codes() = service.retentionHolds(jobId).map { it.code }
        assertTrue(codes().isEmpty(), "unchanged unborn initialization contains no user commits")
        val baseline = f.repositories.commitAll(gitDir, workTree, "local baseline")
        assertEquals(listOf("GIT_UNPUSHED_COMMITS"), codes(), "absence of a remote is not proof of a push")
        f.repositories.git("--git-dir=$gitDir", "update-ref", "refs/remotes/origin/trunk", baseline)
        assertTrue(codes().isEmpty(), "a clean commit contained by a remote-tracking ref is retained elsewhere")
        f.repositories.git("--git-dir=$gitDir", "--work-tree=$workTree", "checkout", "-q", "--detach", baseline)
        Files.writeString(workTree.resolve("new.c"), "int unpushed;\n")
        val detached = f.repositories.commitAll(gitDir, workTree, "detached work")
        assertEquals(listOf("GIT_UNPUSHED_COMMITS"), codes(), "detached commits are still user work")
        f.repositories.git("--git-dir=$gitDir", "tag", "-a", "keep", "-m", "keep detached work", detached)
        f.repositories.git("--git-dir=$gitDir", "--work-tree=$workTree", "checkout", "-q", "trunk")
        assertEquals(listOf("GIT_UNPUSHED_COMMITS"), codes(), "tag-only history must not be discarded")
        f.repositories.git("--git-dir=$gitDir", "tag", "-d", "keep")
        assertTrue(codes().isEmpty())
    }

    @Test fun `a retained snapshot that no longer matches its commitments is never published`(): Unit {
        for (change in listOf("modify", "delete")) Fixture().use { f ->
            if (change == "modify") f.write("src/main file.c", "int main(void) { return 1; }\r\n")
            else Files.delete(f.snapshot.resolve("include/fixture.h"))
            val service = f.open()
            val failed = service.settle(service.request(jobId, GitRepositoryRequest.Init("run_1", "revision_1", null), "changed_snapshot_${change}"))
            assertEquals(GitOperationState.FAILED, failed.state, change)
            assertEquals("SOURCE_REVISION_UNAVAILABLE", failed.failureCode, change)
            assertTrue(service.listing(jobId).repositories.isEmpty())
        }
    }

    @Test fun `an explicit initial branch is validated and invalid requests start no operation`(): Unit = Fixture().use { f ->
        val service = f.open()
        for (branch in listOf("-x", "a..b", "x.lock", "a b")) {
            assertEquals("VALIDATION_FAILED", assertFailsWith<ManagedGitException>(branch) {
                service.request(jobId, GitRepositoryRequest.Init("run_1", "revision_1", branch), "invalid_branch_key_01")
            }.code)
        }
        assertEquals("SOURCE_REVISION_UNAVAILABLE", assertFailsWith<ManagedGitException> {
            service.request(jobId, GitRepositoryRequest.Init("run_1", "revision_other", null), "invalid_revision_key")
        }.code)
        assertEquals("NOT_FOUND", assertFailsWith<ManagedGitException> {
            service.request("f".repeat(32), GitRepositoryRequest.Init("run_1", "revision_1", null), "invalid_job_key_0001")
        }.code)
        assertEquals("IMPORT_UNAVAILABLE", assertFailsWith<ManagedGitException> {
            service.request(jobId, GitRepositoryRequest.Attach("source"), "import_unconfigured_1")
        }.code)
        assertTrue(service.listing(jobId).operations.isEmpty())
        // 200 code points, with each path component below the filesystem's byte limit.
        val branch = List(4) { "🚀".repeat(49) }.joinToString("/") + "x"
        assertEquals("VALIDATION_FAILED", assertFailsWith<ManagedGitException> {
            service.request(jobId, GitRepositoryRequest.Init("run_1", "revision_1", branch + "x"), "unicode_too_long_key")
        }.code)
        assertTrue(service.listing(jobId).operations.isEmpty())
        val completed = service.settle(service.request(jobId, GitRepositoryRequest.Init("run_1", "revision_1", branch), "unicode_branch_key01"))
        assertEquals(GitOperationState.COMPLETED, completed.state)
        assertEquals("refs/heads/$branch", service.workspace(jobId, completed.repositoryId).observation.head.refName)
    }

    @Test fun `unusable Git refuses every operation explicitly`(): Unit = Fixture().use { f ->
        val service = f.open(availability = GitAvailability.Unavailable("GIT_VERSION_UNSUPPORTED", "Git 2.20.1 is older than the required 2.36.0."))
        for (call in listOf<() -> Unit>(
            { service.request(jobId, GitRepositoryRequest.Init("run_1", "revision_1", null), "unavailable_key_0001") },
            { service.listing(jobId) }, { service.workspace(jobId, "repository_x") },
        )) {
            val failure = assertFailsWith<ManagedGitException> { call() }
            assertEquals("CAPABILITY_UNAVAILABLE", failure.code); assertTrue(failure.message!!.contains("2.36.0"))
        }
        assertFalse(f.store.resolve(jobId).resolve("git").exists())
    }

    @Test fun `a snapshot with links or nested repositories is refused without publication`(): Unit = Fixture().use { f ->
        Files.createSymbolicLink(f.snapshot.resolve("escape"), f.repositories.root)
        val service = f.open()
        val failed = service.settle(service.request(jobId, GitRepositoryRequest.Init("run_1", "revision_1", null), "linked_source_key_01"))
        assertEquals(GitOperationState.FAILED, failed.state)
        assertTrue(failed.message.contains("links"))
        assertTrue(service.listing(jobId).repositories.isEmpty())
        assertFalse(f.store.resolve(jobId).resolve("git/staging").let { it.exists() && Files.list(it).use { s -> s.count() } > 0 })
    }

    @Test fun `restart reconciles every interruption point without exposing or overwriting anything`() {
        for (point in GitOperationCrashPoint.entries) Fixture().use { f ->
            val before = f.tree(f.snapshot)
            f.crashes += point
            val first = f.open()
            val admission = first.request(jobId, GitRepositoryRequest.Init("run_1", "revision_1", null), "crash_request_key_01")
            assertTrue(first.awaitIdle(60_000))
            // The crashed instance still shows a non-terminal record and no half-prepared repository.
            if (point != GitOperationCrashPoint.AFTER_PUBLISH) assertTrue(first.listing(jobId).repositories.isEmpty(), point.name)
            first.close()
            f.crashes.clear()
            val restarted = f.open()
            restarted.recover(listOf(jobId))
            val recovered = restarted.operation(jobId, admission.operation.repositoryId, admission.operation.operationId)
            assertEquals(before, f.tree(f.snapshot), point.name)
            assertFalse(f.store.resolve(jobId).resolve("git/staging/${admission.operation.operationId}").exists(), point.name)
            if (point == GitOperationCrashPoint.AFTER_PUBLISH) {
                assertEquals(GitOperationState.COMPLETED, recovered.state, point.name)
                assertEquals(GitHeadState.UNBORN, restarted.workspace(jobId, recovered.repositoryId).observation.head.state)
            } else {
                assertEquals(GitOperationState.INTERRUPTED, recovered.state, point.name)
                assertFalse(recovered.recoveryRequired)
                assertTrue(restarted.listing(jobId).repositories.isEmpty(), point.name)
                // Replay reports the interruption; it never silently repeats the work.
                val replay = restarted.request(jobId, GitRepositoryRequest.Init("run_1", "revision_1", null), "crash_request_key_01")
                assertTrue(replay.replayed); assertEquals(GitOperationState.INTERRUPTED, replay.operation.state)
                // Safe re-entry: a new explicit request initializes normally.
                val retried = restarted.settle(restarted.request(jobId, GitRepositoryRequest.Init("run_1", "revision_1", null), "crash_retry_key_0001"))
                assertEquals(GitOperationState.COMPLETED, retried.state, point.name)
                assertNotEquals(admission.operation.repositoryId, retried.repositoryId)
                assertEquals(before - "build/main.o", f.tree(f.repositoryDirectory(retried.repositoryId).resolve("worktree")))
            }
        }
    }

    @Test fun `publication never replaces an existing directory`(): Unit = Fixture().use { f ->
        var occupied: Path? = null
        val service = ManagedGitRepositories(f.store, GitRuntime.detect(), f.resolver, crash = { point ->
            if (point == GitOperationCrashPoint.BEFORE_PUBLISH) {
                val records = f.store.resolve(jobId).resolve("git/operations")
                val record = Files.list(records).use { files -> Files.readString(files.toList().single()) }
                val repositoryId = Regex("\"repositoryId\":\"(repository_[0-9a-f]{32})\"").find(record)!!.groupValues[1]
                occupied = Files.createDirectories(f.store.resolve(jobId).resolve("git/repositories").resolve(repositoryId)).also {
                    Files.writeString(it.resolve("keep"), "existing")
                }
            }
        })
        service.use {
            val failed = it.settle(it.request(jobId, GitRepositoryRequest.Init("run_1", "revision_1", null), "occupied_target_key1"))
            assertEquals(GitOperationState.FAILED, failed.state)
            assertEquals("PUBLICATION_CONFLICT", failed.failureCode)
            // The occupying directory is untouched and, lacking a registration, is not a repository.
            assertEquals(listOf("keep"), Files.list(occupied!!).use { files -> files.map { file -> file.fileName.toString() }.toList() })
            assertTrue(it.listing(jobId).repositories.isEmpty())
            assertFalse(f.store.resolve(jobId).resolve("git/staging/${failed.operationId}").exists())
        }
    }

    // ---- Import (#572) ------------------------------------------------------------------

    private fun importFixture(): Pair<Fixture, Path> {
        val repositories = GitTestRepositories()
        val importRoot = Files.createDirectories(repositories.root.resolve("admitted imports"))
        return Fixture(repositories, importRoot) to importRoot
    }

    @Test fun `import copies history into an isolated managed repository and keeps hostile content inert`() {
        val (f, importRoot) = importFixture()
        f.use {
            val g = f.repositories
            val source = Files.createDirectories(importRoot.resolve("hostile"))
            g.git("init", "-q", "--initial-branch=develop", source.toString())
            Files.writeString(source.resolve(".gitattributes"), "* filter=evil\nlf.c text eol=crlf\nid.c ident\n")
            Files.write(source.resolve("lf.c"), "int x;\n".toByteArray())
            Files.write(source.resolve("id.c"), "/* \$Id\$ */\n".toByteArray())
            Files.writeString(source.resolve(".gitmodules"), "[submodule \"vendor\"]\n\tpath = vendor\n\turl = ${g.root.resolve("elsewhere")}\n")
            Files.write(source.resolve("raw source.c"), "int raw = 1;\r\n".toByteArray())
            g.git("add", "-A", cwd = source)
            g.git("commit", "-q", "-m", "baseline", cwd = source)
            val vendor = g.git("rev-parse", "HEAD", cwd = source).trim()
            g.git("update-index", "--add", "--cacheinfo", "160000,$vendor,vendor", cwd = source)
            g.git("commit", "-q", "-m", "submodule", cwd = source)
            g.git("tag", "baseline", cwd = source)
            val head = g.git("rev-parse", "HEAD", cwd = source).trim()
            // Hostile configuration and hooks are added after history so fixture commands never meet them.
            val marker = g.root.resolve("import-tripwire")
            val config = source.resolve(".git/config").toString()
            for ((key, value) in listOf("filter.evil.smudge" to "", "filter.evil.clean" to "", "filter.evil.process" to "",
                "core.fsmonitor" to "", "core.hooksPath" to "hooks-dir", "diff.external" to "", "include.path" to "")) {
                val target = if (value.isEmpty()) g.tripwire("$key.sh", marker).toString() else source.resolve(value).toString()
                g.git("config", "--file", config, key, target)
            }
            Files.createDirectories(source.resolve("hooks-dir")); Files.createDirectories(source.resolve(".git/hooks"))
            for (hook in listOf("post-checkout", "post-merge", "reference-transaction", "pre-commit")) {
                Files.copy(g.tripwire("source-$hook.sh", marker), source.resolve(".git/hooks/$hook"), java.nio.file.StandardCopyOption.REPLACE_EXISTING)
            }
            val sourceBefore = f.tree(source)

            val service = f.open()
            val completed = service.settle(service.request(jobId, GitRepositoryRequest.Attach("hostile"), "import_hostile_key_01"))
            assertEquals(GitOperationState.COMPLETED, completed.state, completed.message)
            assertEquals(head, completed.resultObjectId)
            assertFalse(marker.exists())
            assertEquals(sourceBefore, f.tree(source))
            val view = service.workspace(jobId, completed.repositoryId)
            assertEquals(GitHeadObservation(GitHeadState.ATTACHED, "refs/heads/develop", head), view.observation.head)
            assertFalse(view.observation.dirty)
            assertEquals(setOf("refs/heads/develop", "refs/tags/baseline"), view.observation.refs.map { it.name }.toSet())
            val directory = f.repositoryDirectory(completed.repositoryId)
            val workTree = directory.resolve("worktree")
            assertContentEquals("int raw = 1;\r\n".toByteArray(), Files.readAllBytes(workTree.resolve("raw source.c")))
            // Imported eol/ident attributes cannot rewrite checked-out bytes.
            assertContentEquals("int x;\n".toByteArray(), Files.readAllBytes(workTree.resolve("lf.c")))
            assertContentEquals("/* \$Id\$ */\n".toByteArray(), Files.readAllBytes(workTree.resolve("id.c")))
            assertEquals(GitManagedLayout.ATTRIBUTES, Files.readString(directory.resolve("repository.git/info/attributes")))
            assertFalse(workTree.resolve("vendor/.git").exists())
            val gitDir = directory.resolve("repository.git")
            val keys = GitConfigurationAudit.read(g.runner, gitDir.resolve("config")).map { it.first }.toSet()
            assertTrue(keys.none { it.startsWith("filter.") || it.startsWith("include.") || it == "core.fsmonitor" || it == "core.hookspath" })
            assertFalse(gitDir.resolve("hooks").let { it.exists() && Files.list(it).use { s -> s.count() } > 0 })
            assertFalse(gitDir.resolve("modules").exists())
            assertEquals(GitTrackingPolicy.excludeFile(), Files.readString(gitDir.resolve("info/exclude")))
            assertFalse(marker.exists())
        }
    }

    @Test fun `full integrity verification bounds inflation even for a compressed dangling object`() {
        GitTestRepositories().use { g ->
            val (gitDir, _) = g.managed("expansion")
            // Stream a valid 64 MiB loose blob without allocating its expanded contents in the JVM.
            // HEAD is unborn, so a HEAD-tree quota alone would never account for this object.
            val temporary = g.root.resolve("compressed blob")
            val digest = java.security.MessageDigest.getInstance("SHA-1")
            java.util.zip.DeflaterOutputStream(Files.newOutputStream(temporary)).use { compressed ->
                java.security.DigestOutputStream(compressed, digest).use { output ->
                    output.write("blob 67108864\u0000".toByteArray())
                    val zeros = ByteArray(64 * 1024)
                    repeat(1024) { output.write(zeros) }
                }
            }
            assertTrue(Files.size(temporary) < 100_000)
            val id = with(GitStorage) { digest.digest().hex() }
            val loose = GitStorage.directories(gitDir.resolve("objects"), id.take(2)).resolve(id.drop(2))
            Files.move(temporary, loose)
            val before = GitSourceCopy.digestOf(loose)
            // Test with a smaller real OS budget; never run the oversized fsck without a ceiling.
            val failure = assertFailsWith<GitOperationFailure> {
                GitRepositoryImport.verify(g.runner, gitDir, maxAddressSpaceBytes = 48L * 1024 * 1024)
            }
            assertEquals("REPOSITORY_UNSUPPORTED", failure.code)
            assertTrue(failure.message!!.contains("memory budget"))
            assertEquals(before, GitSourceCopy.digestOf(loose))
            assertEquals("REPOSITORY_UNAVAILABLE", assertFailsWith<GitOperationFailure> {
                GitRepositoryImport.verify(GitCommandRunner(g.runner.executable, g.environment, memoryLimiter = null), gitDir)
            }.code)
        }
    }

    @Test fun `object copy rejects a link substituted after stat and pins renamed parent directories`() {
        GitTestRepositories().use { g ->
            val source = Files.createDirectories(g.root.resolve("objects/ab"))
            val external = Files.createDirectories(g.root.resolve("external objects"))
            Files.writeString(external.resolve("blob"), "outside marker")
            val objectFile = Files.writeString(source.resolve("blob"), "original bytes")
            val rejected = Files.createDirectory(g.root.resolve("rejected objects"))
            val failure = assertFailsWith<GitOperationFailure> {
                GitImportObjectCopy.copy(source.parent, rejected) { relative: java.nio.file.Path ->
                    if (relative.toString() == "ab/blob") {
                        Files.delete(objectFile)
                        Files.createSymbolicLink(objectFile, external.resolve("blob"))
                    }
                }
            }
            assertEquals("REPOSITORY_UNSUPPORTED", failure.code)
            assertFalse(Files.exists(rejected.resolve("ab/blob"), NOFOLLOW_LINKS))
            Files.delete(objectFile)
            Files.writeString(objectFile, "original bytes")
            val copied = Files.createDirectory(g.root.resolve("copied objects"))
            GitImportObjectCopy.copy(source.parent, copied) { relative: java.nio.file.Path ->
                if (relative.toString() == "ab/blob") {
                    Files.move(source, source.resolveSibling("old"))
                    Files.createSymbolicLink(source, external)
                }
            }
            val destination = copied.resolve("ab/blob")
            assertFalse(Files.isSymbolicLink(destination))
            assertEquals("original bytes", Files.readString(destination))
            Files.writeString(external.resolve("blob"), "changed outside")
            assertEquals("original bytes", Files.readString(destination))
            // Root/ancestor links are refused too; a final-component no-follow open alone is insufficient.
            assertEquals("REPOSITORY_UNSUPPORTED", assertFailsWith<GitOperationFailure> {
                GitImportObjectCopy.copy(source, Files.createDirectory(g.root.resolve("linked root target")))
            }.code)
        }
    }

    @Test fun `object copy refuses a FIFO substituted after stat without a writer and honors interruption`() {
        GitTestRepositories().use { g ->
            for (interrupt in listOf(false, true)) {
                val source = Files.createDirectory(g.root.resolve("fifo source $interrupt"))
                // An empty regular file and FIFO both report size zero: size alone is not a type check.
                val objectFile = Files.writeString(source.resolve("object"), "")
                val target = Files.createDirectory(g.root.resolve("fifo target $interrupt"))
                val outcome = java.util.concurrent.atomic.AtomicReference<Throwable>()
                val replaced = java.util.concurrent.CountDownLatch(1)
                val copier = Thread {
                    try {
                        GitImportObjectCopy.copy(source, target) { relative: Path ->
                            if (relative.toString() == "object") {
                                Files.delete(objectFile)
                                val mkfifo = ProcessBuilder("/usr/bin/mkfifo", objectFile.toString()).start()
                                try {
                                    check(mkfifo.waitFor(2, java.util.concurrent.TimeUnit.SECONDS) && mkfifo.exitValue() == 0)
                                } finally { if (mkfifo.isAlive) mkfifo.destroyForcibly() }
                                if (interrupt) Thread.currentThread().interrupt()
                                replaced.countDown()
                            }
                        }
                    } catch (failure: Throwable) { outcome.set(failure) }
                }.apply { isDaemon = true; start() }
                try {
                    assertTrue(replaced.await(5, java.util.concurrent.TimeUnit.SECONDS))
                    copier.join(2_000)
                    assertFalse(copier.isAlive, "a FIFO replacement must not require a writer to release the import worker")
                    if (interrupt) assertTrue(outcome.get() is java.io.InterruptedIOException, outcome.get().toString())
                    else assertEquals("REPOSITORY_UNSUPPORTED", (outcome.get() as? GitOperationFailure)?.code)
                    assertFalse(Files.exists(target.resolve("object"), NOFOLLOW_LINKS), "no destination is created for a special file")
                } finally { copier.interrupt() }
            }
        }
    }

    @Test fun `history metadata refuses writer-free FIFO replacement and interruption at every read site`() {
        for (name in listOf("HEAD", "packed-refs", "refs/heads/main", "refs/remotes/origin/main")) {
            for (interrupt in listOf(false, true)) GitTestRepositories().use { g ->
                val source = g.root.resolve("source")
                g.git("init", "-q", "--bare", "--initial-branch=main", source.toString())
                val file = source.resolve(name)
                Files.createDirectories(file.parent)
                if (name != "HEAD") Files.writeString(file, if (name == "packed-refs") "" else "a".repeat(40) + "\n")
                if (name.startsWith("refs/remotes/")) Files.writeString(source.resolve("refs/heads/main"), "ref: $name\n")
                val layout = GitRepositoryImport.layout(g.runner, source)
                val target = g.root.resolve("target")
                g.git("init", "-q", "--bare", target.toString())
                val originalHead = Files.readAllBytes(target.resolve("HEAD"))
                val outcome = java.util.concurrent.atomic.AtomicReference<Throwable>()
                val replaced = java.util.concurrent.CountDownLatch(1)
                val worker = Thread {
                    try {
                        GitRepositoryImport.copyHistory(layout, target, beforeMetadataOpen = { opened ->
                            if (opened == file) {
                                Files.delete(file)
                                makeFifo(file)
                                if (interrupt) Thread.currentThread().interrupt()
                                replaced.countDown()
                            }
                        })
                    } catch (failure: Throwable) { outcome.set(failure) }
                }.apply { isDaemon = true; start() }
                try {
                    assertTrue(replaced.await(5, java.util.concurrent.TimeUnit.SECONDS), name)
                    worker.join(2_000)
                    assertFalse(worker.isAlive, "$name replacement must terminate without a FIFO writer")
                    if (interrupt) assertTrue(outcome.get() is java.io.InterruptedIOException, outcome.get().toString())
                    else assertEquals("REPOSITORY_UNSUPPORTED", (outcome.get() as? GitOperationFailure)?.code, name)
                    assertContentEquals(originalHead, Files.readAllBytes(target.resolve("HEAD")), name)
                } finally { worker.interrupt() }
            }
        }
    }

    @Test fun `imported FIFO metadata fails without publication and permits worker shutdown`() {
        for (name in listOf("HEAD", "packed-refs", "refs/heads/main", "refs/remotes/origin/main")) {
            val (f, importRoot) = importFixture()
            f.use {
                val source = importRoot.resolve("metadata")
                f.repositories.git("init", "-q", "--initial-branch=main", source.toString())
                val gitDir = source.resolve(".git")
                val file = gitDir.resolve(name)
                Files.createDirectories(file.parent)
                Files.deleteIfExists(file)
                makeFifo(file)
                if (name.startsWith("refs/remotes/")) Files.writeString(gitDir.resolve("refs/heads/main"), "ref: $name\n")
                val service = f.open()
                val admission = service.request(jobId, GitRepositoryRequest.Attach("metadata"), "import_metadata_key_0001")
                assertTrue(service.awaitIdle(5_000), name)
                val failed = service.operation(jobId, admission.operation.repositoryId, admission.operation.operationId)
                assertEquals(GitOperationState.FAILED, failed.state, name)
                assertEquals("REPOSITORY_UNSUPPORTED", failed.failureCode, name)
                assertTrue(service.listing(jobId).repositories.isEmpty())
                assertFalse(f.repositoryDirectory(failed.repositoryId).exists())
                assertFalse(f.store.resolve(jobId).resolve("git/staging/${failed.operationId}").exists())
                service.close()
                assertTrue(service.terminated, name)
            }
        }
    }

    @Test fun `metadata reads retain byte bounds and refuse links while pinning renamed ancestors`() {
        GitTestRepositories().use { g ->
            val directory = Files.createDirectory(g.root.resolve("metadata"))
            val file = Files.writeString(directory.resolve("HEAD"), "inside")
            assertEquals("inside", GitImportMetadata.read(file, 6).toString(Charsets.UTF_8))
            assertEquals("REPOSITORY_UNSUPPORTED", assertFailsWith<GitOperationFailure> { GitImportMetadata.read(file, 5) }.code)
            val outside = Files.createDirectory(g.root.resolve("outside"))
            Files.writeString(outside.resolve("HEAD"), "outside")
            assertEquals("inside", GitImportMetadata.read(file, 6) {
                Files.move(directory, g.root.resolve("pinned"))
                Files.createSymbolicLink(directory, outside)
            }.toString(Charsets.UTF_8))
            assertEquals("REPOSITORY_UNSUPPORTED", assertFailsWith<GitOperationFailure> { GitImportMetadata.read(file, 4096) }.code)
            val leaf = g.root.resolve("leaf")
            Files.createSymbolicLink(leaf, outside.resolve("HEAD"))
            assertEquals("REPOSITORY_UNSUPPORTED", assertFailsWith<GitOperationFailure> { GitImportMetadata.read(leaf, 4096) }.code)
            assertContentEquals(byteArrayOf(), GitImportMetadata.read(Files.write(g.root.resolve("empty"), byteArrayOf()), 0))
        }
    }

    private fun makeFifo(path: Path) {
        val process = ProcessBuilder("/usr/bin/mkfifo", path.toString()).start()
        try {
            check(process.waitFor(2, java.util.concurrent.TimeUnit.SECONDS) && process.exitValue() == 0)
        } finally { if (process.isAlive) process.destroyForcibly() }
    }

    @Test fun `an imported FIFO object store fails without publication or a lingering worker`() {
        val (f, importRoot) = importFixture()
        f.use {
            val source = importRoot.resolve("fifo")
            f.repositories.git("init", "-q", "--initial-branch=main", source.toString())
            val mkfifo = ProcessBuilder("/usr/bin/mkfifo", source.resolve(".git/objects/fifo").toString()).start()
            try {
                assertTrue(mkfifo.waitFor(2, java.util.concurrent.TimeUnit.SECONDS) && mkfifo.exitValue() == 0)
            } finally { if (mkfifo.isAlive) mkfifo.destroyForcibly() }
            val service = f.open()
            val admission = service.request(jobId, GitRepositoryRequest.Attach("fifo"), "import_fifo_key_0001")
            assertTrue(service.awaitIdle(5_000))
            val failed = service.operation(jobId, admission.operation.repositoryId, admission.operation.operationId)
            assertEquals(GitOperationState.FAILED, failed.state)
            assertEquals("REPOSITORY_UNSUPPORTED", failed.failureCode)
            assertTrue(service.listing(jobId).repositories.isEmpty())
            assertFalse(f.repositoryDirectory(failed.repositoryId).exists())
            assertFalse(f.store.resolve(jobId).resolve("git/staging/${failed.operationId}").exists())
            service.close()
            assertTrue(service.terminated)
        }
    }

    @Test fun `object-store imports charge empty directories against the entry quota before creating them`() {
        GitTestRepositories().use { g ->
            val source = Files.createDirectories(g.root.resolve("wide/objects"))
            repeat(20) { Files.createDirectory(source.resolve("%02x".format(it))) }
            val target = Files.createDirectory(g.root.resolve("wide target"))
            assertEquals("REPOSITORY_UNSUPPORTED", assertFailsWith<GitOperationFailure> {
                GitImportObjectCopy.copy(source, target, maxEntries = 10)
            }.code)
            val created = Files.list(target).use { it.count() }
            assertTrue(created <= 10, "only charged directories may be created, found $created")
            // Within the quota the same layout copies.
            GitImportObjectCopy.copy(source, Files.createDirectory(g.root.resolve("narrow target")), maxEntries = 20)
        }
    }

    @Test fun `reference and work-tree copies charge empty directories before creating them`() {
        GitTestRepositories().use { g ->
            val source = g.root.resolve("wide-refs")
            g.git("init", "-q", "--initial-branch=main", source.toString())
            val heads = source.resolve(".git/refs/heads")
            repeat(20) { Files.createDirectory(heads.resolve("empty$it")) }
            val managed = g.root.resolve("managed.git")
            g.git("init", "-q", "--bare", "--initial-branch=main", managed.toString())
            val layout = ImportedRepositoryLayout(source.resolve(".git"), false, GitObjectFormat.SHA1)
            assertEquals("REPOSITORY_UNSUPPORTED", assertFailsWith<GitOperationFailure> {
                GitRepositoryImport.copyHistory(layout, managed, maxRefEntries = 10)
            }.code)
            val created = Files.list(managed.resolve("refs/heads")).use { it.count() }
            assertTrue(created <= 10, "only charged reference directories may be created, found $created")
            // Snapshot copies into a work tree are bounded the same way.
            val snapshot = Files.createDirectories(g.root.resolve("wide-snapshot"))
            repeat(20) { Files.createDirectory(snapshot.resolve("d$it")) }
            val workTree = Files.createDirectory(g.root.resolve("wide-worktree"))
            assertEquals("SOURCE_UNSUPPORTED", assertFailsWith<GitOperationFailure> {
                GitSourceCopy.copy(snapshot, workTree, emptySet(), maxDirectories = 10)
            }.code)
            assertTrue(Files.list(workTree).use { it.count() } <= 10)
            GitSourceCopy.copy(snapshot, Files.createDirectory(g.root.resolve("narrow-worktree")), emptySet(), maxDirectories = 20)
        }
    }

    @Test fun `import resolves symbolic branches and tags before dropping their target namespaces`() {
        for (format in listOf("sha1", "sha256")) {
            val (f, importRoot) = importFixture()
            f.use {
                val g = f.repositories
                val source = importRoot.resolve("symbolic")
                g.git("init", "-q", "--initial-branch=main", "--object-format=$format", source.toString())
                Files.writeString(source.resolve("file.c"), "int value;\n")
                g.git("add", "-A", cwd = source); g.git("commit", "-q", "-m", "baseline", cwd = source)
                val head = g.git("rev-parse", "HEAD", cwd = source).trim()
                g.git("update-ref", "refs/remotes/origin/main", head, cwd = source)
                g.git("pack-refs", "--all", cwd = source)
                g.git("symbolic-ref", "refs/heads/main", "refs/remotes/origin/main", cwd = source)
                g.git("symbolic-ref", "refs/tags/alias", "refs/heads/main", cwd = source)
                g.git("fsck", "--full", "--no-dangling", cwd = source)
                val before = f.tree(source)
                val service = f.open()
                val completed = service.settle(service.request(jobId, GitRepositoryRequest.Attach("symbolic"), "import_symbolic_key_01"))
                assertEquals(GitOperationState.COMPLETED, completed.state, completed.message)
                val view = service.workspace(jobId, completed.repositoryId)
                assertEquals(GitHeadObservation(GitHeadState.ATTACHED, "refs/heads/main", head), view.observation.head)
                assertEquals(setOf("refs/heads/main", "refs/tags/alias"), view.observation.refs.map { it.name }.toSet())
                val gitDir = f.repositoryDirectory(completed.repositoryId).resolve("repository.git")
                for (ref in listOf("refs/heads/main", "refs/tags/alias")) assertEquals("$head\n", Files.readString(gitDir.resolve(ref)))
                assertEquals(before, f.tree(source))
            }
        }
    }

    @Test fun `import refuses cyclic and excessive symbolic reference chains without publishing`() {
        for (cyclic in listOf(true, false)) {
            val (f, importRoot) = importFixture()
            f.use {
                val source = importRoot.resolve("chain")
                f.repositories.git("init", "-q", "--initial-branch=main", source.toString())
                Files.writeString(source.resolve(".git/refs/heads/main"), "ref: refs/remotes/link0\n")
                val remotes = Files.createDirectories(source.resolve(".git/refs/remotes"))
                repeat(20) { i -> Files.writeString(remotes.resolve("link$i"), "ref: refs/remotes/link${if (cyclic) 0 else i + 1}\n") }
                val before = f.tree(source)
                val service = f.open()
                val failed = service.settle(service.request(jobId, GitRepositoryRequest.Attach("chain"), "import_ref_chain_key1"))
                assertEquals("REPOSITORY_UNSUPPORTED", failed.failureCode)
                assertTrue(service.listing(jobId).repositories.isEmpty())
                assertEquals(before, f.tree(source))
            }
        }
    }

    @Test fun `import bounds directory expansion before checkout and counts shared prefixes only once`() {
        for (format in listOf("sha1", "sha256")) for (maxDirectories in listOf(5, 6)) {
            val (f, importRoot) = importFixture()
            f.use {
                val g = f.repositories
                val source = importRoot.resolve("directories")
                g.git("init", "-q", "--initial-branch=main", "--object-format=$format", source.toString())
                // Four empty files share six directories; neither the file nor byte quota is exceeded.
                for (prefix in listOf("a/b/c", "d/e/f")) {
                    val directory = Files.createDirectories(source.resolve(prefix))
                    repeat(2) { Files.writeString(directory.resolve("file$it.c"), "") }
                }
                g.git("add", "-A", cwd = source); g.git("commit", "-q", "-m", "deep prefixes", cwd = source)
                val before = f.tree(source)
                val service = f.open(limits = GitCheckoutLimits(maxFiles = 4, maxBytes = 1, maxDirectories = maxDirectories))
                val operation = service.settle(service.request(jobId, GitRepositoryRequest.Attach("directories"), "import_directories_key1"))
                if (maxDirectories == 5) {
                    assertEquals(GitOperationState.FAILED, operation.state, "$format must refuse excess directories")
                    assertEquals("REPOSITORY_UNSUPPORTED", operation.failureCode)
                    assertTrue(service.listing(jobId).repositories.isEmpty())
                    assertFalse(f.repositoryDirectory(operation.repositoryId).exists())
                } else {
                    assertEquals(GitOperationState.COMPLETED, operation.state, operation.message)
                    val workTree = f.repositoryDirectory(operation.repositoryId).resolve("worktree")
                    assertEquals(6L, Files.walk(workTree).use { paths -> paths.filter { it != workTree && Files.isDirectory(it) }.count() })
                    assertEquals(4, f.tree(workTree).size)
                }
                assertFalse(f.store.resolve(jobId).resolve("git/staging/${operation.operationId}").exists())
                assertEquals(before, f.tree(source))
            }
        }
    }

    @Test fun `checkout directory quota includes inert gitlinks`() {
        GitTestRepositories().use { g ->
            val (gitDir, workTree) = g.managed("gitlink-directories")
            Files.writeString(workTree.resolve("file.c"), "")
            val commit = g.commitAll(gitDir, workTree, "baseline")
            for (path in listOf("vendor1", "vendor2")) {
                g.git("--git-dir=$gitDir", "--work-tree=$workTree", "update-index", "--add", "--cacheinfo", "160000,$commit,$path")
            }
            g.git("--git-dir=$gitDir", "--work-tree=$workTree", "commit", "-q", "-m", "inert gitlinks")
            val head = g.git("--git-dir=$gitDir", "rev-parse", "HEAD").trim()
            assertEquals("REPOSITORY_UNSUPPORTED", assertFailsWith<GitOperationFailure> {
                GitRepositoryImport.requireCheckoutBounds(g.runner, gitDir, head, GitCheckoutLimits(maxDirectories = 1))
            }.code)
            GitRepositoryImport.requireCheckoutBounds(g.runner, gitDir, head, GitCheckoutLimits(maxDirectories = 2))
            // Preflight only reads: the submodule directories have not yet been materialized.
            assertFalse(workTree.resolve("vendor1").exists()); assertFalse(workTree.resolve("vendor2").exists())
        }
    }

    @Test fun `import keeps every valid tag, refuses unimportable refs, altered objects and oversized checkouts`() {
        val (f, importRoot) = importFixture()
        f.use {
            val g = f.repositories
            fun repository(name: String, files: Map<String, ByteArray>): Path {
                val source = Files.createDirectories(importRoot.resolve(name))
                g.git("init", "-q", "--initial-branch=main", source.toString())
                files.forEach { (path, bytes) -> Files.write(source.resolve(path), bytes) }
                g.git("add", "-A", cwd = source); g.git("commit", "-q", "-m", name, cwd = source)
                return source
            }
            fun attempt(name: String, limits: GitCheckoutLimits = GitCheckoutLimits()): Pair<GitOperationRecord, ManagedGitRepositories> {
                val service = f.open(limits = limits)
                return service.settle(service.request(jobId, GitRepositoryRequest.Attach(name), "import_${name}_key_00001")) to service
            }
            fun clear(service: ManagedGitRepositories) { service.close(); f.store.resolve(jobId).resolve("git").toFile().deleteRecursively() }

            // A packed tag named HEAD is a valid full ref name and must survive import.
            val tagged = repository("tagged", mapOf("a.c" to "int a;\n".toByteArray()))
            g.git("update-ref", "refs/tags/HEAD", g.git("rev-parse", "HEAD", cwd = tagged).trim(), cwd = tagged)
            g.git("tag", "v1.0", cwd = tagged)
            g.git("pack-refs", "--all", cwd = tagged)
            val (imported, service) = attempt("tagged")
            assertEquals(GitOperationState.COMPLETED, imported.state, imported.message)
            assertEquals(setOf("refs/heads/main", "refs/tags/HEAD", "refs/tags/v1.0"),
                service.workspace(jobId, imported.repositoryId).observation.refs.map { it.name }.toSet())
            clear(service)

            // An unimportable branch or tag fails explicitly instead of silently disappearing.
            val locked = repository("locked", mapOf("a.c" to "int a;\n".toByteArray()))
            val head = g.git("rev-parse", "HEAD", cwd = locked).trim()
            Files.writeString(locked.resolve(".git/packed-refs"), "# pack-refs with: peeled fully-peeled sorted \n$head refs/tags/x.lock\n")
            val (refused, refusedService) = attempt("locked")
            assertEquals(GitOperationState.FAILED, refused.state); assertEquals("REPOSITORY_UNSUPPORTED", refused.failureCode)
            clear(refusedService)

            // A loose blob replaced by validly compressed, same-length different content is corrupt.
            val altered = repository("altered", mapOf("a.c" to "abcd\n".toByteArray()))
            val blob = g.git("rev-parse", "HEAD:a.c", cwd = altered).trim()
            val loose = altered.resolve(".git/objects/${blob.take(2)}/${blob.drop(2)}")
            Files.delete(loose)
            java.util.zip.DeflaterOutputStream(Files.newOutputStream(loose)).use { it.write("blob 5\u0000wxyz\n".toByteArray()) }
            val (corrupt, corruptService) = attempt("altered")
            assertEquals(GitOperationState.FAILED, corrupt.state); assertEquals("REPOSITORY_CORRUPT", corrupt.failureCode)
            assertTrue(corruptService.listing(jobId).repositories.isEmpty())
            clear(corruptService)

            // Forty paths sharing one compressible blob expand far beyond the object store's size.
            val zeros = ByteArray(64 * 1024)
            repository("expanding", (1..40).associate { "copy$it.bin" to zeros })
            val (expanded, expandedService) = attempt("expanding", GitCheckoutLimits(maxBytes = 1024 * 1024))
            assertEquals(GitOperationState.FAILED, expanded.state); assertEquals("REPOSITORY_UNSUPPORTED", expanded.failureCode)
            assertFalse(f.store.resolve(jobId).resolve("git/staging/${expanded.operationId}").exists())
            val (fewer, fewerService) = attempt("expanding".also { clear(expandedService) }, GitCheckoutLimits(maxFiles = 10))
            assertEquals("REPOSITORY_UNSUPPORTED", fewer.failureCode)
            clear(fewerService)
        }
    }

    @Test fun `import validation distinguishes bare detached unborn sha256 corrupt and unsupported repositories`() {
        val (f, importRoot) = importFixture()
        f.use {
            val g = f.repositories
            fun commitIn(repository: Path, branch: String, format: String = "sha1"): String {
                g.git("init", "-q", "--initial-branch=$branch", "--object-format=$format", repository.toString())
                Files.writeString(repository.resolve("file.c"), "/* $branch */\n")
                g.git("add", "-A", cwd = repository); g.git("commit", "-q", "-m", branch, cwd = repository)
                return g.git("rev-parse", "HEAD", cwd = repository).trim()
            }
            val work = Files.createDirectories(g.root.resolve("work"))
            val bareHead = commitIn(work, "release")
            g.git("clone", "-q", "--bare", work.toString(), importRoot.resolve("bare.git").toString())
            Files.writeString(importRoot.resolve("bare.git/HEAD"), "$bareHead\n")
            g.git("init", "-q", "--initial-branch=empty", importRoot.resolve("unborn").toString())
            val wideHead = commitIn(Files.createDirectories(importRoot.resolve("wide")), "wide", "sha256")
            val corrupt = Files.createDirectories(importRoot.resolve("corrupt"))
            commitIn(corrupt, "broken")
            val blob = g.git("rev-parse", "HEAD:file.c", cwd = corrupt).trim()
            Files.delete(corrupt.resolve(".git/objects/${blob.take(2)}/${blob.drop(2)}"))
            val alternates = Files.createDirectories(importRoot.resolve("alternates"))
            commitIn(alternates, "alt")
            Files.writeString(alternates.resolve(".git/objects/info/alternates"), work.resolve(".git/objects").toString() + "\n")
            val gitfile = Files.createDirectories(importRoot.resolve("gitfile"))
            Files.writeString(gitfile.resolve(".git"), "gitdir: ${work.resolve(".git")}\n")
            val partial = Files.createDirectories(importRoot.resolve("partial"))
            commitIn(partial, "partial")
            g.git("config", "--file", partial.resolve(".git/config").toString(), "core.repositoryformatversion", "1")
            g.git("config", "--file", partial.resolve(".git/config").toString(), "extensions.partialClone", "origin")
            Files.createDirectories(importRoot.resolve("plain")).resolve("readme.txt").let { Files.writeString(it, "not a repository") }
            Files.createSymbolicLink(importRoot.resolve("linked"), work)

            fun attempt(name: String): Pair<GitOperationRecord, ManagedGitRepositories> {
                val service = f.open()
                return service.settle(service.request(jobId, GitRepositoryRequest.Attach(name), "import_${name.replace('.', '_')}_key_000001")) to service
            }
            fun clear() { f.store.resolve(jobId).resolve("git").toFile().deleteRecursively() }

            for ((name, expectedHead, state) in listOf(Triple("bare.git", bareHead, GitHeadState.DETACHED),
                Triple("unborn", null, GitHeadState.UNBORN), Triple("wide", wideHead, GitHeadState.ATTACHED))) {
                val (operation, service) = attempt(name)
                assertEquals(GitOperationState.COMPLETED, operation.state, "$name: ${operation.message}")
                val view = service.workspace(jobId, operation.repositoryId)
                assertEquals(state, view.observation.head.state, name); assertEquals(expectedHead, view.observation.head.objectId, name)
                assertEquals("imported", view.record.origin); assertNull(view.record.candidateRevisionId)
                if (name == "wide") assertEquals(GitObjectFormat.SHA256, view.observation.objectFormat)
                if (name == "unborn") assertEquals("refs/heads/empty", view.observation.head.refName)
                service.close(); clear()
            }
            for ((name, code) in listOf("corrupt" to "REPOSITORY_CORRUPT", "alternates" to "REPOSITORY_UNSUPPORTED",
                "gitfile" to "REPOSITORY_UNSUPPORTED", "partial" to "REPOSITORY_UNSUPPORTED", "plain" to "REPOSITORY_UNSUPPORTED")) {
                val (operation, service) = attempt(name)
                assertEquals(GitOperationState.FAILED, operation.state, name)
                assertTrue(operation.message.isNotBlank() && !operation.message.contains(importRoot.toString()), name)
                assertEquals(code, operation.failureCode, "$name: ${operation.message}")
                assertTrue(service.listing(jobId).repositories.isEmpty(), name)
                service.close(); clear()
            }
            val service = f.open()
            for (name in listOf("linked", "missing")) {
                assertEquals("IMPORT_SOURCE_UNAVAILABLE", assertFailsWith<ManagedGitException>(name) {
                    service.request(jobId, GitRepositoryRequest.Attach(name), "import_refused_key_01")
                }.code)
            }
            for (name in listOf("../work", "a/b", ".hidden", "", "x.lock")) {
                assertEquals("VALIDATION_FAILED", assertFailsWith<ManagedGitException>(name) {
                    service.request(jobId, GitRepositoryRequest.Attach(name), "import_invalid_key_01")
                }.code)
            }
            assertTrue(service.listing(jobId).operations.isEmpty())
        }
    }

    @Test fun `shutdown reports a Git worker that outlives its wait, and storage loops stop on interruption`() {
        Fixture().use { f ->
            // A worker stuck where interruption cannot reach it: close() must not claim it stopped.
            val release = java.util.concurrent.CountDownLatch(1)
            val entered = java.util.concurrent.CountDownLatch(1)
            val service = ManagedGitRepositories(f.store, GitRuntime.detect(), f.resolver, policy = GitRepositoryPolicy(defaultBranch = "trunk"),
                crash = { point ->
                    if (point == GitOperationCrashPoint.AFTER_RUNNING) {
                        entered.countDown()
                        while (release.count > 0) try { release.await() } catch (_: InterruptedException) { /* ignores shutdown */ }
                    }
                }, shutdownTimeout = java.time.Duration.ofMillis(200))
            service.request(jobId, GitRepositoryRequest.Init("run_1", "revision_1", null), "shutdown_key_00001")
            assertTrue(entered.await(30, java.util.concurrent.TimeUnit.SECONDS))
            service.close()
            assertFalse(service.terminated, "a running worker must keep the store owned")
            release.countDown()
            val deadline = System.nanoTime() + java.time.Duration.ofSeconds(30).toNanos()
            while (!service.terminated && System.nanoTime() < deadline) Thread.sleep(10)
            assertTrue(service.terminated)
            // Copy and cleanup loops stop at their next step once the worker is interrupted.
            val target = Files.createDirectories(f.repositories.root.resolve("interrupted copy"))
            Thread.currentThread().interrupt()
            try {
                assertFailsWith<java.io.InterruptedIOException> { GitSourceCopy.copy(f.snapshot, target) }
                assertFailsWith<java.io.InterruptedIOException> { GitStorage.deleteTree(f.snapshot) }
            } finally { Thread.interrupted() }
            assertTrue(Files.exists(f.snapshot.resolve("CMakeLists.txt")))
        }
    }
}
