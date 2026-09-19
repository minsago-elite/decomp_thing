package decompengine.project

import java.nio.file.Path
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

class GeneratedCBuildLifecycleTest {
    private fun project(profile: ReconstructionProfile): Path = createTempDirectory("build-lifecycle-").also {
        it.resolve("src").createDirectories().resolve("main.c").writeText("int main(void) { return 0; }\n")
        it.resolve(profile.layout.declaration("build-definition").materialize()).writeText("# authored lifecycle fixture\n")
    }

    private fun configuration(profile: ReconstructionProfile, timeout: Long = 10_000) = ProjectBuildConfiguration(
        buildDefinition = profile.layout.declaration("build-definition").materialize(),
        wallClockTimeoutMillis = timeout,
        terminationGraceMillis = 0,
    )

    @Test
    fun `prelaunch cancellation preserves existing build files`() {
        val profile = GeneratedCMakeReconstructionProfile.descriptor
        val project = project(profile)
        val artifact = project.resolve("build").createDirectories().resolve("reconstructed")
        artifact.writeText("previous artifact")
        val failure = AtomicReference<Throwable?>()
        val worker = Thread {
            Thread.currentThread().interrupt()
            try {
                GeneratedCProjectBuilder.build(project, configuration(profile), profile)
            } catch (error: Throwable) {
                failure.set(error)
            }
        }
        worker.start()
        worker.join(5_000)
        assertFalse(worker.isAlive)
        assertIs<InterruptedException>(failure.get())
        assertEquals("previous artifact", artifact.readText())
        assertFalse(project.resolve("BUILDING.md").exists())
    }

    @Test
    fun `running build cancellation terminates the owned process for both profiles`() {
        for (profile in ReconstructionProfiles.builtIn) {
            val project = project(profile)
            val ready = project.resolve("ready")
            val invocation = GeneratedCBuildInvocation(
                listOf("/bin/sh", "-c", "printf '%s\\n' \"\$\$\" > \"\$1\"; exec /bin/sleep 10", "authored-build", ready.toString()),
                listOf("POSIX shell", "sleep"), "Authored lifecycle fixture.",
            )
            val failure = AtomicReference<Throwable?>()
            val worker = Thread {
                try {
                    GeneratedCProjectBuilder.build(project, configuration(profile), profile, invocation)
                } catch (error: Throwable) {
                    failure.set(error)
                }
            }
            var process: ProcessHandle? = null
            try {
                worker.start()
                val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
                var pid: Long? = null
                while (pid == null && worker.isAlive && System.nanoTime() < deadline) {
                    pid = if (ready.exists()) ready.readText().trim().toLongOrNull() else null
                    if (pid == null) Thread.sleep(5)
                }
                process = ProcessHandle.of(requireNotNull(pid) { "build did not start: ${failure.get()}" }).orElseThrow()
                assertTrue(process.isAlive)
                worker.interrupt()
                worker.join(5_000)
                assertFalse(worker.isAlive)
                assertIs<InterruptedException>(failure.get())
                assertFalse(process.isAlive)
                assertFalse(project.resolve("reports/build_contract.json").exists())
            } finally {
                process?.let { if (it.isAlive) it.destroyForcibly() }
                if (worker.isAlive) worker.interrupt()
                worker.join(5_000)
            }
        }
    }

    @Test
    fun `build deadline stops a quiet command without publishing a contract`() {
        val profile = GeneratedCMakeReconstructionProfile.descriptor
        val project = project(profile)
        val failure = AtomicReference<Throwable?>()
        val worker = Thread {
            try {
                GeneratedCProjectBuilder.build(project, configuration(profile, 100), profile,
                    GeneratedCBuildInvocation(listOf("/bin/sleep", "2"), listOf("sleep"), "Authored deadline fixture."))
            } catch (error: Throwable) {
                failure.set(error)
            }
        }
        try {
            worker.start()
            worker.join(1_500)
            assertFalse(worker.isAlive, "deadline must complete before the authored command's normal exit")
            assertTrue(assertIs<BuildException>(failure.get()).message.orEmpty().contains("exceeded 100 milliseconds"))
            assertFalse(project.resolve("reports/build_contract.json").exists())
        } finally {
            if (worker.isAlive) worker.interrupt()
            worker.join(5_000)
        }
    }
}
