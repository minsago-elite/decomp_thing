package decompengine.project

import decompengine.oracle.fulltree.inControlTemporaryDirectory
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlin.io.path.exists
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
        val supervisor = start("/bin/sh", "-c", "touch '$marker'")
        supervisor.outputStream.close()

        assertEquals(120, awaitExit(supervisor))
        assertFalse(marker.exists())
    }

    @Test
    fun `worker status is reported only after the tree is gone`() {
        assertEquals(7, run("/bin/sh", "-c", "exit 7"))
        assertEquals(100, run("/bin/sh", "-c", "exit 200"))
        assertEquals(101, run("/bin/sh", "-c", "kill -KILL $$"))
    }

    @Test
    fun `reparented grandchild is adopted and killed before absence is proven`() = inControlTemporaryDirectory { root ->
        val orphanFile = root.resolve("orphan")
        // The subshell exits at once, so the TERM-ignoring sleep is orphaned while the worker runs.
        val supervisor = start("/bin/sh", "-c",
            "( (trap '' TERM; exec sleep 30) & echo \$! > '$orphanFile' ); exec sleep 30")
        supervisor.outputStream.write("1\n".toByteArray())
        supervisor.outputStream.flush()
        val orphan = awaitPid(orphanFile)
        awaitParent(orphan, supervisor.pid())

        supervisor.outputStream.write('T'.code)
        supervisor.outputStream.flush()

        assertEquals(101, awaitExit(supervisor), "the worker ends by SIGTERM; the supervisor then kills the orphan")
        assertFalse(alive(orphan), "the orphan ignored SIGTERM but cannot outlive the supervisor's proof")
    }

    @Test
    fun `descendants left after the worker exits are killed`() = inControlTemporaryDirectory { root ->
        val orphanFile = root.resolve("orphan")
        val supervisor = start("/bin/sh", "-c", "(trap '' TERM; exec sleep 30) & echo \$! > '$orphanFile'; exit 0")
        supervisor.outputStream.write("1\n".toByteArray())
        supervisor.outputStream.flush()

        assertEquals(0, awaitExit(supervisor))
        assertFalse(alive(awaitPid(orphanFile)))
        supervisor.outputStream.close()
    }

    @Test
    fun `closing the control channel kills the whole tree`() = inControlTemporaryDirectory { root ->
        val workerFile = root.resolve("worker")
        val supervisor = start("/bin/sh", "-c", "echo $$ > '$workerFile'; exec sleep 30")
        supervisor.outputStream.write("1\n".toByteArray())
        supervisor.outputStream.flush()
        val worker = awaitPid(workerFile)

        supervisor.outputStream.close()

        assertEquals(101, awaitExit(supervisor))
        assertFalse(alive(worker))
    }

    @Test
    fun `a process reusing an exited descendant's PID in the same clock tick is never signalled`() = inControlTemporaryDirectory { root ->
        assumeTrue(namespacesAvailable(), "unprivileged user and PID namespaces are unavailable on this host")
        var sameTickRuns = 0
        // PID reuse is forced each run; reuse inside one 10 ms clock tick depends on scheduling, so retry for it.
        for (attempt in 1..20) {
            val work = Files.createDirectory(root.resolve("run-$attempt"))
            val result = namespacedReuse(work)
            assertEquals(result.getValue("x"), result.getValue("s"), "ns_last_pid must force the stranger onto the exited PID")
            assertEquals("yes", result.getValue("alive"), "the stranger at the reused PID must survive the kill: $result")
            assertEquals("101", result.getValue("status"), "the supervisor must still prove its own tree absent: $result")
            if (result.getValue("xstart") == result.getValue("sstart")) sameTickRuns++
            if (sameTickRuns > 0) break
        }
        assertTrue(sameTickRuns > 0, "no run reused the PID within one clock tick")
    }

    // Inside a fresh user and PID namespace, a worker descendant X records its own start tick, exits and
    // is reaped by the worker. The namespace's init then sets ns_last_pid so its own unrelated child S
    // receives X's PID, and only then asks the supervisor to kill its tree.
    private fun namespacedReuse(work: Path): Map<String, String> {
        val driver = """
            set -eu
            sup=${'$'}1 work=${'$'}2
            mkfifo "${'$'}work/go" "${'$'}work/reaped"
            { printf '1\n'; read release < "${'$'}work/go"; printf K; } | "${'$'}sup" /bin/sh -c '
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
            sleep 30 & s=${'$'}!
            sstart=${'$'}(cut -d" " -f22 /proc/${'$'}s/stat)
            echo > "${'$'}work/go"
            status=0
            wait ${'$'}supervisor || status=${'$'}?
            alive=no
            if kill -0 ${'$'}s 2>/dev/null; then alive=yes; fi
            kill -KILL ${'$'}s 2>/dev/null || true
            read xstart < "${'$'}work/xstart"
            echo "x=${'$'}x s=${'$'}s xstart=${'$'}xstart sstart=${'$'}sstart status=${'$'}status alive=${'$'}alive"
        """.trimIndent()
        val process = ProcessBuilder("unshare", "-Urpfm", "--mount-proc", "/bin/sh", "-c", driver, "driver",
            supervisor().toString(), work.toString()).redirectErrorStream(true).start()
        process.outputStream.close()
        val output = String(process.inputStream.readNBytes(64 * 1024), Charsets.UTF_8)
        assertTrue(process.waitFor(30, TimeUnit.SECONDS), output)
        assertEquals(0, process.exitValue(), output)
        return output.lineSequence().last { it.startsWith("x=") }.split(' ')
            .associate { field -> field.substringBefore('=') to field.substringAfter('=') }
    }

    private fun namespacesAvailable(): Boolean = runCatching {
        val probe = ProcessBuilder("unshare", "-Urpfm", "--mount-proc", "/bin/sh", "-c",
            "echo 1 > /proc/sys/kernel/ns_last_pid").redirectErrorStream(true).start()
        probe.outputStream.close()
        probe.inputStream.readNBytes(4096)
        probe.waitFor(10, TimeUnit.SECONDS) && probe.exitValue() == 0
    }.getOrDefault(false)

    private fun supervisor(): Path = Path.of(requireNotNull(System.getProperty("decompengine.export.supervisorExecutable")) {
        "the built export supervisor is not configured"
    })

    private fun start(vararg worker: String): Process =
        ProcessBuilder(listOf(supervisor().toString()) + worker).redirectError(ProcessBuilder.Redirect.DISCARD)
            .redirectOutput(ProcessBuilder.Redirect.DISCARD).start()

    private fun run(vararg worker: String): Int {
        val supervisor = start(*worker)
        supervisor.outputStream.write("1\n".toByteArray())
        supervisor.outputStream.flush()
        return awaitExit(supervisor).also { supervisor.outputStream.close() }
    }

    private fun awaitExit(process: Process): Int {
        if (!process.waitFor(10, TimeUnit.SECONDS)) {
            process.outputStream.close()
            check(process.waitFor(5, TimeUnit.SECONDS)) { "supervisor did not exit after its control channel closed" }
        }
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

    private fun alive(pid: Long): Boolean {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
        while (System.nanoTime() < deadline) {
            if (!ProcessHandle.of(pid).map { it.isAlive }.orElse(false)) return false
            Thread.sleep(5)
        }
        return true
    }
}
