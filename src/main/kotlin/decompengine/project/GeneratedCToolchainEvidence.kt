package decompengine.project

import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Local version observations are not authenticated executable identities. */
internal object GeneratedCToolchainEvidence {
    fun render(profile: ReconstructionProfile): String {
        val compiler = profile.adapterConfiguration.getValue("compiler-driver").single()
        val build = profile.adapterConfiguration["build-executable"]?.singleOrNull() ?: "make"
        val millis = minOf(profile.budgets.buildWallClockMillis, 2_000L)
        val bytes = minOf(profile.budgets.buildMaximumOutputBytes, 16_384L).toInt()
        return JsonObject(linkedMapOf(
            "decompEngineVersion" to JsonPrimitive("0.1.0"),
            "javaVersion" to JsonPrimitive(System.getProperty("java.version")),
            "compilerCommand" to JsonPrimitive(compiler),
            "compilerVersion" to JsonPrimitive(probe(listOf(compiler, "--version"), millis, bytes)),
            "buildCommand" to JsonPrimitive(build),
            "buildVersion" to JsonPrimitive(probe(listOf(build, "--version"), millis, bytes)),
            "note" to JsonPrimitive("Local bounded version observations; executable identity is not authenticated. LLM model and prompt hashes are recorded per generated module when applicable."),
        )).toString() + "\n"
    }

    internal fun probe(command: List<String>, maximumMillis: Long, maximumBytes: Int): String {
        require(maximumMillis in 1..2_000 && maximumBytes in 1..16_384)
        if (Thread.interrupted()) throw InterruptedException("toolchain observation cancelled")
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(maximumMillis)
        var process: Process? = null
        var reader: CompletableFuture<ByteArray>? = null
        try {
            val builder = ProcessBuilder(command).redirectErrorStream(true)
            MakeProjectBuilder.sanitizeBuildEnvironment(builder.environment())
            val running = builder.start()
            process = running
            running.outputStream.close()
            val output = CompletableFuture.supplyAsync { running.inputStream.readNBytes(maximumBytes + 1) }
            reader = output
            val bytes = output.get(maxOf(1L, deadline - System.nanoTime()), TimeUnit.NANOSECONDS)
            if (bytes.size > maximumBytes) return "unavailable"
            if (!running.waitFor(maxOf(1L, deadline - System.nanoTime()), TimeUnit.NANOSECONDS) || running.exitValue() != 0) {
                return "unavailable"
            }
            return bytes.decodeToString(throwOnInvalidSequence = true).lineSequence().firstOrNull().orEmpty()
        } catch (interrupted: InterruptedException) {
            throw interrupted
        } catch (failure: Exception) {
            if (Thread.currentThread().isInterrupted) {
                Thread.interrupted()
                throw InterruptedException("toolchain observation cancelled").also { it.initCause(failure) }
            }
            return "unavailable"
        } finally {
            process?.let { running ->
                MakeProjectBuilder.terminateBuildProcess(running, 0)
                running.inputStream.close()
            }
            reader?.cancel(true)
        }
    }
}
