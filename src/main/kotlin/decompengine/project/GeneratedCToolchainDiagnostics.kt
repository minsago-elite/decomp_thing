package decompengine.project

import decompengine.doctor.CommandProbe
import decompengine.doctor.DoctorCheck
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.pathString
import kotlin.io.path.writeText

/** Generated-C diagnostics run only an authored compiler/runtime capability probe. */
internal class GeneratedCToolchainDiagnostics(
    private val buildSystem: String,
    private val buildName: String,
) : ToolchainDiagnosticPolicy {
    override fun prepare(profile: ReconstructionProfile): PreparedToolchainDiagnostics {
        require(profile.adapterConfiguration["build-system"] == listOf(buildSystem)) {
            "selected profile build-system must be $buildSystem for $buildName diagnostics"
        }
        val compilerDriver = requireNotNull(profile.adapterConfiguration["compiler-driver"]?.singleOrNull()) {
            "selected profile compiler-driver must contain exactly one executable"
        }
        val buildExecutable = requireNotNull(profile.adapterConfiguration["build-executable"]?.singleOrNull()) {
            "selected profile build-executable must contain exactly one executable"
        }
        return Prepared(compilerDriver, listOf(
            ToolchainVersionProbe(
                "C compiler",
                listOf(compilerDriver, "--version"),
                "Install the selected C compiler and ensure $compilerDriver is executable.",
            ),
            ToolchainVersionProbe(
                buildName,
                listOf(buildExecutable, "--version"),
                "Install $buildName and ensure $buildExecutable is executable.",
            ),
        ))
    }

    private class Prepared(
        private val compilerDriver: String,
        override val versionProbes: List<ToolchainVersionProbe>,
    ) : PreparedToolchainDiagnostics {
        override fun checkCapabilities(commandProbe: CommandProbe): List<DoctorCheck> =
            listOf(sanitizerCheck(commandProbe))

        private fun sanitizerCheck(commandProbe: CommandProbe): DoctorCheck {
            requireNotInterrupted()
            val directory = try {
                Files.createTempDirectory("llm-bin-patch-doctor-")
            } catch (failure: Exception) {
                requireNotInterrupted(failure)
                return DoctorCheck("C sanitizers", false,
                    "Could not create a temporary directory to test AddressSanitizer/UBSan: ${failure.message}")
            }
            var result: DoctorCheck? = null
            var primaryFailure: Throwable? = null
            try {
                result = compileAndRunProbe(commandProbe, directory)
            } catch (failure: Throwable) {
                primaryFailure = failure
            } finally {
                try {
                    if (!directory.toFile().deleteRecursively()) {
                        throw IOException("could not remove the temporary sanitizer probe directory")
                    }
                } catch (cleanupFailure: Throwable) {
                    val original = primaryFailure
                    if (original == null) primaryFailure = cleanupFailure
                    else if (cleanupFailure !== original) original.addSuppressed(cleanupFailure)
                }
            }
            requireNotInterrupted(primaryFailure)
            val failure = primaryFailure
            if (failure != null) {
                if (failure !is Exception) throw failure
                val detail = result?.let {
                    "${it.detail} Could not clean up the temporary sanitizer probe: ${failure.message}"
                } ?: "Could not compile and run the sanitizer probe using $compilerDriver: ${failure.message}"
                return DoctorCheck("C sanitizers", false, detail)
            }
            return checkNotNull(result)
        }

        private fun compileAndRunProbe(commandProbe: CommandProbe, directory: Path): DoctorCheck {
            val source = directory.resolve("probe.c")
            val binary = directory.resolve("probe")
            source.writeText("int main(void) { return 0; }\n")
            requireNotInterrupted()
            val compile = commandProbe.run(
                listOf(compilerDriver, "-std=c11", "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                    source.pathString, "-o", binary.pathString),
                directory,
            )
            requireNotInterrupted()
            if (compile.exitCode != 0) {
                return DoctorCheck("C sanitizers", false,
                    "$compilerDriver could not link an AddressSanitizer/UBSan probe; install sanitizer runtime libraries. " +
                        compile.output.firstLineOr("no compiler output"))
            }
            val run = commandProbe.run(listOf(binary.pathString), directory)
            requireNotInterrupted()
            return if (run.exitCode == 0) {
                DoctorCheck("C sanitizers", true, "AddressSanitizer and UBSan probe compiled and ran")
            } else {
                DoctorCheck("C sanitizers", false,
                    "The sanitizer probe exited ${run.exitCode}; verify sanitizer runtime libraries. ${run.output.firstLineOr("no output")}")
            }
        }

        private fun requireNotInterrupted(failure: Throwable? = null) {
            if (failure is InterruptedException) throw failure
            if (Thread.currentThread().isInterrupted) {
                throw InterruptedException("C sanitizer diagnostics cancelled").also {
                    if (failure != null) it.initCause(failure)
                }
            }
        }
    }
}

private fun String.firstLineOr(fallback: String): String = lineSequence().firstOrNull { it.isNotBlank() }?.trim() ?: fallback
