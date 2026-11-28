package decompengine.project

import decompengine.oracle.fulltree.inControlTemporaryDirectory
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlin.io.path.exists
import kotlin.io.path.readLines
import kotlin.io.path.readText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue

/** Real-process checks of the built decomp-export-supervisor; no fixture replaces the kernel. */
class ExportSupervisorNativeTest {
    @Test
    fun `no launch permit starts no worker`() = inControlTemporaryDirectory { root ->
        val marker = root.resolve("worker-started")
        supervised(start("/bin/sh", "-c", "touch '$marker'")) { supervisor ->
            supervisor.outputStream.close()

            assertEquals(120, exitOnItsOwn(supervisor))
            assertFalse(marker.exists())
        }
    }

    @Test
    fun `worker status is reported only after the tree is gone`() {
        assertEquals(7, run("/bin/sh", "-c", "exit 7"))
        assertEquals(100, run("/bin/sh", "-c", "exit 200"))
        assertEquals(101, run("/bin/sh", "-c", "kill -KILL $$"))
    }

    @Test
    fun `an inherited ignored SIGCHLD cannot let the kernel reap the worker`() {
        // An ignored SIGCHLD survives exec; without SIG_DFL the kernel would reap the worker and drop its status.
        val supervisor = ProcessBuilder("/bin/sh", "-c", "trap '' CHLD; exec \"\$0\" 0 /bin/sh -c 'exit 7'", supervisor().toString())
            .redirectError(ProcessBuilder.Redirect.DISCARD).redirectOutput(ProcessBuilder.Redirect.DISCARD).start()
        supervised(supervisor) {
            permit(it)
            assertEquals(7, exitOnItsOwn(it))
        }
    }

    @Test
    fun `T alone ends the tree, and a reparented grandchild is adopted and killed`() = inControlTemporaryDirectory { root ->
        val orphanFile = root.resolve("orphan")
        // The subshell exits at once, so the TERM-ignoring sleep is orphaned while the worker runs.
        supervised(start("/bin/sh", "-c", "( (trap '' TERM; exec sleep 30) & echo \$! > '$orphanFile' ); exec sleep 30")) { supervisor ->
            permit(supervisor)
            val orphan = awaitPid(orphanFile)
            awaitParent(orphan, supervisor.pid())

            supervisor.outputStream.write('T'.code)
            supervisor.outputStream.flush()

            // The control channel stays open: only T may end this tree, not end-of-file cleanup.
            assertEquals(101, exitOnItsOwn(supervisor), "the worker ends by SIGTERM; the supervisor then kills the orphan")
            assertFalse(alive(orphan), "the orphan ignored SIGTERM but cannot outlive the supervisor's proof")
        }
    }

    @Test
    fun `descendants adopted while the supervisor kills are killed too`() = inControlTemporaryDirectory { root ->
        val spawned = root.resolve("spawned")
        // A TERM-ignoring child keeps forking TERM-ignoring grandchildren until it is killed itself.
        supervised(start("/bin/sh", "-c",
            "(trap '' TERM; while :; do (trap '' TERM; exec sleep 30) & echo \$! >> '$spawned'; sleep 0.02; done) & " +
                "exec sleep 30")) { supervisor ->
            permit(supervisor)
            val ready = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
            while ((!spawned.exists() || spawned.readLines().size < 5) && System.nanoTime() < ready) Thread.sleep(10)
            assertTrue(spawned.exists() && spawned.readLines().size >= 5, "the child did not start forking grandchildren")

            supervisor.outputStream.write('K'.code)
            supervisor.outputStream.flush()

            assertEquals(101, exitOnItsOwn(supervisor))
            val pids = spawned.readLines().mapNotNull { it.trim().toLongOrNull() }
            assertTrue(pids.size >= 5)
            assertTrue(pids.none(::alive), "every adopted grandchild must be killed before the supervisor exits")
        }
    }

    @Test
    fun `descendants left after the worker exits get SIGTERM, then SIGKILL after the leftover grace`() =
        inControlTemporaryDirectory { root ->
            val politeFile = root.resolve("polite")
            val stubbornFile = root.resolve("stubborn")
            val politeExit = root.resolve("polite-exited")
            // Each leftover installs its trap before the worker exits, so SIGTERM cannot arrive first.
            supervised(startWithGrace(400, "/bin/sh", "-c",
                "(trap 'touch \"$politeExit\"; exit 0' TERM; touch '$root/polite-ready'; while :; do sleep 0.05; done) & " +
                    "echo \$! > '$politeFile'; (trap '' TERM; touch '$root/stubborn-ready'; exec sleep 30) & " +
                    "echo \$! > '$stubbornFile'; while [ ! -e '$root/polite-ready' ] || [ ! -e '$root/stubborn-ready' ]; do sleep 0.01; done; exit 0")) { supervisor ->
                val started = System.nanoTime()
                permit(supervisor)

                assertEquals(0, exitOnItsOwn(supervisor))
                val elapsedMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)
                assertTrue(politeExit.exists(), "a leftover first receives SIGTERM")
                assertFalse(alive(awaitPid(politeFile)))
                assertFalse(alive(awaitPid(stubbornFile)), "a TERM-ignoring leftover is killed after the grace")
                assertTrue(elapsedMillis >= 400, "the stubborn leftover kept the supervisor alive for the grace: $elapsedMillis ms")
            }
        }

    @Test
    fun `closing the control channel kills the whole tree`() = inControlTemporaryDirectory { root ->
        val workerFile = root.resolve("worker")
        supervised(start("/bin/sh", "-c", "echo $$ > '$workerFile'; exec sleep 30")) { supervisor ->
            permit(supervisor)
            val worker = awaitPid(workerFile)

            supervisor.outputStream.close()

            assertEquals(101, exitOnItsOwn(supervisor))
            assertFalse(alive(worker))
        }
    }

    @Test
    fun `a stop report from a traced worker is not its termination`() {
        val python = Path.of("/usr/bin/python3")
        assumeTrue(Files.isExecutable(python), "python3 is needed to call PTRACE_TRACEME")
        assumeTrue(runCatching { Files.readString(Path.of("/proc/sys/kernel/yama/ptrace_scope")).trim() != "3" }.getOrDefault(true))
        // The worker makes the supervisor its tracer and stops; waitpid reports that stop even without WUNTRACED.
        val worker = "import ctypes, os, signal\n" +
            "assert ctypes.CDLL(None, use_errno=True).ptrace(0, 0, None, None) == 0\n" +
            "os.kill(os.getpid(), signal.SIGSTOP)\nos._exit(0)\n"
        supervised(start(python.toString(), "-I", "-c", worker)) { supervisor ->
            permit(supervisor)

            assertFalse(supervisor.waitFor(700, TimeUnit.MILLISECONDS), "a stopped worker has not terminated")

            supervisor.outputStream.write('K'.code)
            supervisor.outputStream.flush()
            assertEquals(101, exitOnItsOwn(supervisor), "K kills the stopped, traced worker")
        }
    }

    @Test
    fun `a procfs from another PID namespace or another filesystem starts no worker`() = inControlTemporaryDirectory { root ->
        requireNamespaces()
        val marker = root.resolve("worker-started")
        val worker = listOf("/bin/sh", "-c", "touch '$marker'")
        // A new PID namespace whose /proc still shows the parent namespace.
        val foreign = namespaced(listOf("unshare", "-Urpf", supervisor().toString(), "0") + worker)
        assertEquals(121 to true, foreign.first to foreign.second.contains("/proc belongs to another PID namespace"), foreign.second)
        // A mount namespace with a tmpfs over /proc.
        val notProc = namespaced(listOf("unshare", "-Urm", "/bin/sh", "-c", "mount -t tmpfs none /proc && exec \"\$@\"", "sh",
            supervisor().toString(), "0") + worker)
        assertEquals(121 to true, notProc.first to notProc.second.contains("/proc is not procfs"), notProc.second)
        assertFalse(marker.exists(), "no worker may start without the supervisor's own procfs")
    }

    @Test
    fun `an ancestor procfs at an equal PID number starts no worker`() = inControlTemporaryDirectory { root ->
        requireNamespaces()
        // Namespace A mounts its own /proc. A nested PID namespace B keeps A's /proc, and both ns_last_pid
        // values place the supervisor at PID 300 in A and in B, so /proc/self matches getpid() there.
        val driver = """
            set -eu
            sup=${'$'}1 work=${'$'}2 q=300
            mkfifo "${'$'}work/ready" "${'$'}work/go"
            printf '1\n' > "${'$'}work/permit"
            unshare -pf /bin/sh -c '
                sup=${'$'}1 work=${'$'}2 q=${'$'}3
                echo > "${'$'}work/ready"
                read go < "${'$'}work/go"
                echo ${'$'}((q - 1)) > /proc/sys/kernel/ns_last_pid
                "${'$'}sup" 0 /bin/sh -c "touch \"\${'$'}0/worker-started\"" "${'$'}work" < "${'$'}work/permit" 2> "${'$'}work/stderr" &
                s=${'$'}!
                status=0
                wait ${'$'}s || status=${'$'}?
                echo "inner=${'$'}s status=${'$'}status" > "${'$'}work/result"
            ' inner "${'$'}sup" "${'$'}work" "${'$'}q" &
            read ready < "${'$'}work/ready"
            echo ${'$'}((q - 1)) > /proc/sys/kernel/ns_last_pid
            echo > "${'$'}work/go"
            wait
            cat "${'$'}work/result"
        """.trimIndent()
        val result = driverResult(driver, root)
        val diagnostic = root.resolve("stderr").readText()
        assertEquals("300", result.getValue("inner"), "the supervisor must hold PID 300 in the inner namespace: $result")
        assertEquals("121", result.getValue("status"), diagnostic)
        // This check runs after the /proc/self comparison, so reaching it shows the numbers were equal.
        assertTrue(diagnostic.contains("/proc belongs to an ancestor PID namespace"), diagnostic)
        assertFalse(root.resolve("worker-started").exists(), "no worker may start over an ancestor procfs")
    }

    @Test
    fun `a child that reuses the worker's PID cannot replace the worker's status`() = inControlTemporaryDirectory { root ->
        requireNamespaces()
        // After the supervisor reaps the worker (exit 7), a leftover forks a process onto the worker's PID,
        // orphans it to the supervisor, and that process exits 99.
        val driver = """
            set -eu
            sup=${'$'}1 work=${'$'}2
            { printf '1\n'; sleep 2; } | "${'$'}sup" 1000 /bin/sh -c '
                w=${'$'}${'$'} out=${'$'}1
                echo ${'$'}w > "${'$'}out/worker"
                (
                    trap "" TERM
                    touch "${'$'}out/leftover-ready"
                    while kill -0 ${'$'}w 2>/dev/null; do sleep 0.01; done
                    echo ${'$'}((w - 1)) > /proc/sys/kernel/ns_last_pid
                    /bin/sh -c "echo \${'$'}\${'$'} > \"${'$'}out/reuser\"; sleep 0.3; exit 99" &
                    exit 0
                ) &
                # The leftover installs its trap before the worker exits, so the drain SIGTERM cannot arrive first.
                while [ ! -e "${'$'}out/leftover-ready" ]; do sleep 0.01; done
                exit 7' worker "${'$'}work" &
            supervisor=${'$'}!
            status=0
            wait ${'$'}supervisor || status=${'$'}?
            read worker < "${'$'}work/worker"
            read reuser < "${'$'}work/reuser"
            echo "worker=${'$'}worker reuser=${'$'}reuser status=${'$'}status"
        """.trimIndent()
        val result = driverResult(driver, root)
        assertEquals(result.getValue("worker"), result.getValue("reuser"), "the leftover's child must take the worker's PID: $result")
        assertEquals("7", result.getValue("status"), "only the worker's first termination counts: $result")
    }

    @Test
    fun `a process reusing an exited descendant's PID in the same clock tick is never signalled`() = inControlTemporaryDirectory { root ->
        requireNamespaces()
        var sameTickRuns = 0
        // PID reuse is forced each run; reuse inside one 10 ms clock tick depends on scheduling, so retry for it.
        for (attempt in 1..20) {
            val work = Files.createDirectory(root.resolve("run-$attempt"))
            val result = namespacedReuse(work)
            assertEquals(result.getValue("x"), result.getValue("s"), "ns_last_pid must force the stranger onto the exited PID")
            assertEquals("yes", result.getValue("alive"), "the stranger at the reused PID must answer after the kill: $result")
            assertEquals("101", result.getValue("status"), "the supervisor must still prove its own tree absent: $result")
            if (result.getValue("xstart") == result.getValue("sstart")) sameTickRuns++
            if (sameTickRuns > 0) break
        }
        assertTrue(sameTickRuns > 0, "no run reused the PID within one clock tick")
    }

    // Inside a fresh user and PID namespace, a worker descendant X records its own start tick, exits and
    // is reaped by the worker. The namespace's init then sets ns_last_pid so its own unrelated child S
    // receives X's PID, and only then asks the supervisor to kill its tree. S proves it is still running
    // by answering on a FIFO, which a zombie cannot do.
    private fun namespacedReuse(work: Path): Map<String, String> {
        val driver = """
            set -eu
            sup=${'$'}1 work=${'$'}2
            mkfifo "${'$'}work/go" "${'$'}work/reaped" "${'$'}work/ping" "${'$'}work/pong"
            { printf '1\n'; read release < "${'$'}work/go"; printf K; } | "${'$'}sup" 0 /bin/sh -c '
                w=${'$'}1
                /bin/sh -c "f=\${'$'}1; read -r st < /proc/\${'$'}\${'$'}/stat; set -- \${'$'}st; echo \"\${'$'}{22}\" > \"\${'$'}f\"" x "${'$'}w/xstart" & x=${'$'}!
                wait ${'$'}x
                echo ${'$'}x > "${'$'}w/x"
                echo > "${'$'}w/reaped"
                exec sleep 30' worker "${'$'}work" &
            supervisor=${'$'}!
            read ignored < "${'$'}work/reaped"
            read x < "${'$'}work/x"
            echo ${'$'}((x - 1)) > /proc/sys/kernel/ns_last_pid
            /bin/sh -c 'read ping < "${'$'}1/ping"; echo alive > "${'$'}1/pong"' stranger "${'$'}work" & s=${'$'}!
            sstart=${'$'}(cut -d" " -f22 /proc/${'$'}s/stat)
            echo > "${'$'}work/go"
            status=0
            wait ${'$'}supervisor || status=${'$'}?
            exec 3<>"${'$'}work/ping"
            echo ping >&3
            alive=no
            if [ "${'$'}(timeout 5 cat "${'$'}work/pong" || true)" = alive ]; then alive=yes; fi
            read xstart < "${'$'}work/xstart"
            echo "x=${'$'}x s=${'$'}s xstart=${'$'}xstart sstart=${'$'}sstart status=${'$'}status alive=${'$'}alive"
        """.trimIndent()
        return driverResult(driver, work)
    }

    // Runs [driver] as init of a fresh user, PID and mount namespace and parses its last key=value line.
    private fun driverResult(driver: String, work: Path): Map<String, String> {
        val (status, output) = namespaced(listOf("unshare", "-Urpfm", "--mount-proc", "/bin/sh", "-c", driver, "driver",
            supervisor().toString(), work.toString()))
        assertEquals(0, status, output)
        val fields = Regex("""[a-z]+=\S*( [a-z]+=\S*)+""")
        return output.lineSequence().last { fields.matches(it) }
            .split(' ').associate { field -> field.substringBefore('=') to field.substringAfter('=') }
    }

    private fun namespaced(command: List<String>): Pair<Int, String> {
        val process = ProcessBuilder(command).redirectErrorStream(true).start()
        process.outputStream.close()
        val output = java.util.concurrent.CompletableFuture.supplyAsync {
            String(process.inputStream.readNBytes(64 * 1024), Charsets.UTF_8)
        }
        val exited = process.waitFor(30, TimeUnit.SECONDS)
        if (!exited) process.destroyForcibly()
        assertTrue(exited, "namespace driver did not finish")
        return process.exitValue() to output.get(5, TimeUnit.SECONDS)
    }

    // Hosted CI sets the requirement, so the namespace checks fail there instead of being skipped.
    private fun requireNamespaces() {
        if (namespacesAvailable()) return
        check(System.getenv("DECOMP_REQUIRE_EXPORT_SUPERVISOR_NAMESPACES") != "true") {
            "unprivileged user and PID namespaces are required for the export supervisor checks"
        }
        assumeTrue(false, "unprivileged user and PID namespaces are unavailable on this host")
    }

    private fun namespacesAvailable(): Boolean = runCatching {
        namespaced(listOf("unshare", "-Urpfm", "--mount-proc", "/bin/sh", "-c", "echo 1 > /proc/sys/kernel/ns_last_pid")).first == 0
    }.getOrDefault(false)

    private fun supervisor(): Path = Path.of(requireNotNull(System.getProperty("decompengine.export.supervisorExecutable")) {
        "the built export supervisor is not configured"
    })

    private fun start(vararg worker: String): Process = startWithGrace(0, *worker)

    private fun startWithGrace(leftoverGraceMillis: Int, vararg worker: String): Process =
        ProcessBuilder(listOf(supervisor().toString(), leftoverGraceMillis.toString()) + worker)
            .redirectError(ProcessBuilder.Redirect.DISCARD).redirectOutput(ProcessBuilder.Redirect.DISCARD).start()

    private fun permit(supervisor: Process) {
        supervisor.outputStream.write("1\n".toByteArray())
        supervisor.outputStream.flush()
    }

    private fun run(vararg worker: String): Int = supervised(start(*worker)) { supervisor ->
        permit(supervisor)
        exitOnItsOwn(supervisor)
    }

    // Assertions run with the control channel open; closing it (and so K) is only the fixture's cleanup.
    private fun <T> supervised(supervisor: Process, body: (Process) -> T): T {
        try {
            return body(supervisor)
        } finally {
            runCatching { supervisor.outputStream.close() }
            if (!supervisor.waitFor(5, TimeUnit.SECONDS)) supervisor.destroyForcibly()
        }
    }

    private fun exitOnItsOwn(process: Process): Int {
        assertTrue(process.waitFor(10, TimeUnit.SECONDS), "supervisor did not exit while its control channel stayed open")
        return process.exitValue()
    }

    private fun awaitPid(file: Path): Long {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
        while (System.nanoTime() < deadline) {
            if (file.exists()) file.readText().trim().toLongOrNull()?.let { return it }
            Thread.sleep(5)
        }
        error("no PID was written to $file")
    }

    private fun awaitParent(pid: Long, parent: Long) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
        while (System.nanoTime() < deadline) {
            if (ProcessHandle.of(pid).flatMap { it.parent() }.map { it.pid() }.orElse(-1L) == parent) return
            Thread.sleep(5)
        }
        error("process $pid was not adopted by the supervisor $parent")
    }

    // The supervisor reaps every child before it exits, so no zombie of its tree can remain here.
    private fun alive(pid: Long): Boolean {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
        while (System.nanoTime() < deadline) {
            if (!ProcessHandle.of(pid).map { it.isAlive }.orElse(false)) return false
            Thread.sleep(5)
        }
        return true
    }
}
