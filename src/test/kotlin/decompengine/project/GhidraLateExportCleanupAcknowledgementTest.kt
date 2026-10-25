package decompengine.project

import decompengine.analysis.BoundedAnalysisProcessLaunch
import decompengine.analysis.GhidraAnalysisException
import decompengine.oracle.fulltree.inControlTemporaryDirectory
import java.lang.reflect.InvocationTargetException
import java.nio.file.Path
import java.time.Duration
import java.util.concurrent.Executor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.locks.LockSupport
import java.util.concurrent.locks.ReentrantLock
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue

/** Investigation controls: real owned processes, no Ghidra execution or global launch-owner mutation. */
class GhidraLateExportCleanupAcknowledgementTest {
    @Test
    fun `absent native handle before Java acknowledgement reproduces cleanup failure and isolated owner latch`(): Unit =
        inControlTemporaryDirectory { root ->
            withOwnedProcess(root) { process ->
                val owner = BoundedAnalysisProcessLaunch(Executor(Runnable::run))
                withExitAcknowledgementHeld(process) {
                    stopNativeHandle(process)
                    assertTrue(process.isAlive, "Java exit acknowledgement must still be gated")
                    val refusal = abandon(owner, process)
                    assertEquals(1, refusal.suppressed.size)
                    val cleanup = refusal.suppressed.single()
                    assertTrue(cleanup is GhidraAnalysisException)
                    assertEquals("late export worker did not stop within its cleanup allowance", cleanup.message)
                    assertFalse(process.toHandle().isAlive, "cleanup failure must not be mistaken for a native live PID")
                    assertTrue(process.isAlive, "only the Java notification remains deliberately withheld")
                    println("LATE_EXIT_ORDER nativeAbsent=true javaAcknowledged=false cleanupRefused=true isolatedOwner=true")
                }
                assertTrue(process.waitFor(2, TimeUnit.SECONDS), "released Java notification did not settle")
                val unexpectedStart = AtomicBoolean()
                val next = assertFailsWith<GhidraAnalysisException> {
                    owner.start({}, { unexpectedStart.set(true); process }, ::cleanupLateProcess)
                }
                assertEquals("analysis launch is unavailable after an unconfirmed late-worker cleanup", next.message)
                assertFalse(unexpectedStart.get(), "a later acknowledgement must not bypass the retained safety latch")
            }
        }

    @Test
    fun `acknowledged Java exit before cleanup preserves successful cleanup and next isolated admission`(): Unit =
        inControlTemporaryDirectory { root ->
            withOwnedProcess(root) { process ->
                process.destroyForcibly()
                assertTrue(process.waitFor(2, TimeUnit.SECONDS))
                assertFalse(process.toHandle().isAlive)
                val owner = BoundedAnalysisProcessLaunch(Executor(Runnable::run))
                assertTrue(abandon(owner, process).suppressed.isEmpty())
                val admitted = AtomicBoolean()
                assertSame(process, owner.start({}, { admitted.set(true); process }, ::cleanupLateProcess))
                assertTrue(admitted.get())
                println("LATE_EXIT_ORDER nativeAbsent=true javaAcknowledged=true cleanupRefused=false nextAdmission=true")
            }
        }

    @Test
    fun `bounded owned Process wait acknowledges the same native exit while notification lock was held`(): Unit =
        inControlTemporaryDirectory { root ->
            withOwnedProcess(root) { process ->
                withExitAcknowledgementHeld(process) {
                    stopNativeHandle(process)
                    assertTrue(process.isAlive)
                    // Process.waitFor releases the Java exit condition lock while awaiting its acknowledgement.
                    // This discriminating control changes no production cleanup budget or implementation.
                    assertTrue(process.waitFor(2, TimeUnit.SECONDS))
                    assertFalse(process.isAlive)
                    assertFalse(process.toHandle().isAlive)
                    cleanupLateProcess(process)
                    println("LATE_EXIT_ORDER nativeAbsent=true ownedBoundedWait=true javaAcknowledged=true cleanupRefused=false")
                }
            }
        }

    private fun abandon(owner: BoundedAnalysisProcessLaunch, process: Process): AuthoredAbandonment {
        val failure = AuthoredAbandonment()
        val actual = assertFailsWith<AuthoredAbandonment> {
            owner.start({ phase -> if (phase == "while starting export process") throw failure },
                { process }, ::cleanupLateProcess)
        }
        assertSame(failure, actual)
        return actual
    }

    private class AuthoredAbandonment : RuntimeException("controlled caller abandonment after completed process creation")

    private fun cleanupLateProcess(process: Process) {
        try {
            cleanup.invoke(null, process, Duration.ZERO)
        } catch (failure: InvocationTargetException) {
            throw failure.targetException
        }
    }

    private fun withExitAcknowledgementHeld(process: Process, action: () -> Unit) {
        assertEquals("java.lang.ProcessImpl", process.javaClass.name)
        // The exact local Temurin21.0.12.1 source is retained in build/verification/jdk-source.
        // Only this focused investigation task opens java.lang for the controlled ordering.
        val field = process.javaClass.getDeclaredField("lock").apply { isAccessible = true }
        val lock = field.get(process) as ReentrantLock
        lock.lock()
        try { action() } finally { lock.unlock() }
    }

    private fun stopNativeHandle(process: Process) {
        val handle = process.toHandle()
        assertTrue(handle.isAlive)
        assertTrue(handle.destroyForcibly())
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
        while (handle.isAlive && System.nanoTime() < deadline) LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(1))
        assertFalse(handle.isAlive, "owned native process must terminate within the original two-second fixture bound")
    }

    private fun withOwnedProcess(root: Path, action: (Process) -> Unit) {
        val process = ProcessBuilder("/bin/sleep", "30").directory(root.toFile()).start()
        var failure: Throwable? = null
        fun clean(step: () -> Unit) {
            try { step() } catch (caught: Throwable) {
                val original = failure
                if (original == null) failure = caught else if (original !== caught) original.addSuppressed(caught)
            }
        }
        try { action(process) } catch (caught: Throwable) { failure = caught }
        finally {
            clean { if (process.toHandle().isAlive) process.destroyForcibly() }
            clean { assertTrue(process.waitFor(2, TimeUnit.SECONDS), "owned fixture process cleanup was not acknowledged") }
            clean { assertFalse(process.toHandle().isAlive, "owned fixture native PID remains alive") }
            clean { process.outputStream.close() }
            clean { process.inputStream.close() }
            clean { process.errorStream.close() }
        }
        failure?.let { throw it }
    }

    companion object {
        private val cleanup = Class.forName("decompengine.project.ArchivalReconstructionKt")
            .getDeclaredMethod("stopLateExportProcess", Process::class.java, Duration::class.java)
            .apply { isAccessible = true }
    }
}
