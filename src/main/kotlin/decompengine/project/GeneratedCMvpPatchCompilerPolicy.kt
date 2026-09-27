package decompengine.project

import java.nio.file.Path
import kotlin.io.path.pathString

/** Compiler command for the standalone generated-C MVP patch workflow. */
internal interface MvpPatchCompilerPolicy {
    fun command(
        profile: ReconstructionProfile,
        source: Path,
        target: Path,
        sanitizer: Boolean,
        warningsAsErrors: Boolean,
    ): List<String>
}

internal object GeneratedCMvpPatchCompilerPolicy : MvpPatchCompilerPolicy {
    override fun command(
        profile: ReconstructionProfile,
        source: Path,
        target: Path,
        sanitizer: Boolean,
        warningsAsErrors: Boolean,
    ): List<String> {
        val driver = profile.adapterConfiguration["compiler-driver"]?.singleOrNull()
            ?: throw IllegalArgumentException("selected MVP patch profile has no compiler driver")
        val command = mutableListOf(driver, "-std=c11", "-O1", "-g", "-Wall", "-Wextra")
        if (warningsAsErrors) command += "-Werror"
        if (sanitizer) command += listOf(
            "-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=0", "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
        ) else command += listOf(
            "-D_FORTIFY_SOURCE=2", "-fstack-protector-strong", "-fPIE", "-pie", "-Wl,-z,relro,-z,now",
        )
        command += listOf(source.pathString, "-o", target.pathString)
        return command
    }
}
