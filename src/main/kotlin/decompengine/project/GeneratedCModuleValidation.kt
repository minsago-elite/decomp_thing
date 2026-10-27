package decompengine.project

import kotlinx.serialization.json.JsonPrimitive
import java.io.ByteArrayOutputStream
import java.nio.file.Path
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.io.path.readBytes

/** Workflow-owned compiler evidence; ACP completion alone never establishes compilability. */
internal data class ModuleCompilationEvidence(
    val sourceSha256: String,
    val command: List<String>,
    val outcome: String,
    val returnCode: Int?,
    val diagnosticsSha256: String,
    val diagnosticsBytes: Long,
    val diagnosticsPrefix: String = "",
) {
    val passed: Boolean get() = outcome == "passed" && returnCode == 0

    fun toJson(): String = buildString {
        append("{\"sourceSha256\":\"").append(sourceSha256).append("\",\"command\":[")
        append(command.joinToString(",") { JsonPrimitive(it).toString() })
        append("],\"outcome\":\"").append(outcome).append("\",\"returnCode\":")
        append(returnCode ?: "null")
        append(",\"diagnosticsSha256\":\"").append(diagnosticsSha256)
        append("\",\"diagnosticsBytes\":").append(diagnosticsBytes).append('}')
    }
}

/** Generated-C policy is kept beside the explicit generated-C profile. */
internal object GeneratedCModuleValidation {
    const val POLICY_ID = "generated-c-module-validation-v3"

    fun command(profile: ReconstructionProfile, sourcePath: String): List<String> {
        val configuration = ProjectBuildConfiguration(
            compilerExecutable = profile.adapterConfiguration["compiler-driver"]?.singleOrNull()
                ?: error("reconstruction profile must declare its compiler driver"),
            cFlags = profile.adapterConfiguration["compiler-flags"]
                ?: error("reconstruction profile must declare its compiler flags"),
        )
        val implementation = profile.layout.declaration("module-implementation")
        val template = implementation.pathTemplate
        val prefix = template.substringBefore("{module}")
        val suffix = template.substringAfter("{module}")
        require("{module}" in template && sourcePath.startsWith(prefix) && sourcePath.endsWith(suffix))
        val module = sourcePath.substring(prefix.length, sourcePath.length - suffix.length)
        require(implementation.materialize(mapOf("module" to module)) == sourcePath)
        val headers = listOf(
            profile.layout.declaration("shared-interface").materialize(),
            profile.layout.declaration("module-interface").materialize(mapOf("module" to module)),
            profile.layout.declaration("module-private-interface").materialize(mapOf("module" to module)),
        )
        return listOf(configuration.compilerExecutable) + configuration.cFlags +
            headers.flatMap { listOf("-include", it) } + listOf("-c", sourcePath, "-o", "/dev/null")
    }

    fun validate(projectDir: Path, sourcePath: String, profile: ReconstructionProfile): ModuleCompilationEvidence {
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
        } catch (_: Exception) {
            outcome = if (process == null) "failed-to-start" else "failed"
        } finally {
            process?.let { MakeProjectBuilder.terminateBuildProcess(it, 0) }
        }
        val diagnostics = output.toByteArray()
        return ModuleCompilationEvidence(
            before, command, outcome, returnCode, sha256(diagnostics), diagnostics.size.toLong(),
            diagnostics.copyOfRange(0, minOf(diagnostics.size, 16_384)).toString(Charsets.UTF_8),
        )
    }
}
