package decompengine.project

import java.io.ByteArrayOutputStream
import java.nio.file.Path
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.io.path.readBytes

/** Generated-C policy is kept beside the explicit generated-C profile. */
internal object GeneratedCModuleValidation : ModuleCompilationPolicy {
    const val POLICY_ID = "generated-c-module-validation-v2"
    override val id: String = POLICY_ID
    override val providesCompilerFeedback: Boolean = true

    override fun command(profile: ReconstructionProfile, sourcePath: String): List<String> {
        val configuration = ProjectBuildConfiguration(
            compilerExecutable = profile.adapterConfiguration["compiler-driver"]?.singleOrNull()
                ?: error("reconstruction profile must declare its compiler driver"),
            cFlags = profile.adapterConfiguration["compiler-flags"]
                ?: error("reconstruction profile must declare its compiler flags"),
        )
        return listOf(configuration.compilerExecutable) + configuration.cFlags +
            listOf("-c", sourcePath, "-o", "/dev/null")
    }

    override fun validate(projectDir: Path, sourcePath: String, profile: ReconstructionProfile): ModuleCompilationEvidence {
        if (Thread.interrupted()) throw InterruptedException("module compilation cancelled before launch")
        val command = command(profile, sourcePath)
        val source = projectDir.resolve(sourcePath)
        val before = sha256(source.readBytes())
        val output = ByteArrayOutputStream()
        val outputExceeded = AtomicBoolean(false)
        var returnCode: Int? = null
        var outcome = "failed-to-start"
        var process: Process? = null
        try {
            val builder = ProcessBuilder(command).directory(projectDir.toFile()).redirectErrorStream(true)
            MakeProjectBuilder.sanitizeBuildEnvironment(builder.environment())
            process = builder.start()
            process.outputStream.close()
            val running = process
            val reader = CompletableFuture.runAsync {
                running.inputStream.use { input ->
                    val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        if (output.size().toLong() + count > profile.budgets.buildMaximumOutputBytes) {
                            outputExceeded.set(true)
                            MakeProjectBuilder.terminateBuildProcess(running, 0)
                            break
                        }
                        output.write(buffer, 0, count)
                    }
                }
            }
            val completed = running.waitFor(profile.budgets.buildWallClockMillis, TimeUnit.MILLISECONDS)
            if (!completed) MakeProjectBuilder.terminateBuildProcess(running, 0)
            reader.get(5, TimeUnit.SECONDS)
            returnCode = running.exitValue()
            outcome = when {
                outputExceeded.get() -> "output-limit-exceeded"
                !completed -> "timed-out"
                sha256(source.readBytes()) != before -> "source-changed"
                returnCode == 0 -> "passed"
                else -> "failed"
            }
        } catch (interrupted: InterruptedException) {
            throw interrupted
        } catch (failure: Exception) {
            if (Thread.currentThread().isInterrupted) {
                Thread.interrupted()
                throw InterruptedException("module compilation cancelled").also { it.initCause(failure) }
            }
            outcome = if (process == null) "failed-to-start" else "failed"
        } finally {
            process?.let { MakeProjectBuilder.terminateBuildProcess(it, 0) }
        }
        val diagnostics = output.toByteArray()
        return ModuleCompilationEvidence(
            before, command, outcome, returnCode, sha256(diagnostics), diagnostics.size.toLong(),
            diagnosticsPrefix = diagnosticFeedback(diagnostics, projectDir),
        )
    }

    internal fun diagnosticFeedback(bytes: ByteArray, projectDir: Path, redactedRoots: List<Path> = emptyList()): String {
        var raw = bytes.copyOfRange(0, minOf(bytes.size, 32_768)).toString(Charsets.UTF_8)
        for (root in listOf(projectDir) + redactedRoots) {
            raw = raw.replace(root.toAbsolutePath().normalize().toString(), "<workspace>")
        }
        raw = raw.replace(Regex("\\u001B\\[[0-?]*[ -/]*[@-~]"), "")
        val selected = raw.lineSequence().filter { line ->
            listOf("error:", "fatal error:", "warning:", "undefined reference", "note:").any(line::contains)
        }.map { line ->
            line.replace(Regex("(?:[A-Za-z]:)?/[^\\s:]+(?=:[0-9]+(?::[0-9]+)?:)"), "<path>")
                .filter { it == '\t' || it >= ' ' && it != '\u007f' }
        }.take(32).joinToString("\n")
        val bounded = selected.toByteArray(Charsets.UTF_8)
        return bounded.copyOfRange(0, minOf(bounded.size, 16_384)).toString(Charsets.UTF_8)
    }
}
