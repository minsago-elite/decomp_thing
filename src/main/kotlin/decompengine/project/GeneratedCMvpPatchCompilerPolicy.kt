package decompengine.project

import decompengine.mvp.MvpVulnerabilityCase
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
        vulnerabilityCase: MvpVulnerabilityCase = MvpVulnerabilityCase.OUT_OF_BOUNDS_WRITE,
    ): List<String>

    fun diagnosticCommand(source: Path, vulnerabilityCase: MvpVulnerabilityCase): List<String>
}

internal object GeneratedCMvpPatchCompilerPolicy : MvpPatchCompilerPolicy {
    private val CLANG_EVIDENCE_CASES = setOf(MvpVulnerabilityCase.INTEGER_OVERFLOW, MvpVulnerabilityCase.MEMORY_LEAK)

    override fun command(
        profile: ReconstructionProfile,
        source: Path,
        target: Path,
        sanitizer: Boolean,
        warningsAsErrors: Boolean,
        vulnerabilityCase: MvpVulnerabilityCase,
    ): List<String> {
        val driver = profile.adapterConfiguration["compiler-driver"]?.singleOrNull()
            ?: throw IllegalArgumentException("selected MVP patch profile has no compiler driver")
        // Unsigned-overflow checks and reliable leak reachability need Clang instrumentation; release builds keep the profile driver.
        val evidenceDriver = if (sanitizer && vulnerabilityCase in CLANG_EVIDENCE_CASES) "clang" else driver
        val command = mutableListOf(evidenceDriver, "-std=c11", "-O1", "-g", "-Wall", "-Wextra")
        if (warningsAsErrors) command += "-Werror"
        if (sanitizer) command += listOf(
            "-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=0", "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
        ) else command += listOf(
            "-D_FORTIFY_SOURCE=2", "-fstack-protector-strong", "-fPIE", "-pie", "-Wl,-z,relro,-z,now",
        )
        if (sanitizer && vulnerabilityCase == MvpVulnerabilityCase.INTEGER_OVERFLOW) command += "-fsanitize=unsigned-integer-overflow"
        command += listOf(source.pathString, "-o", target.pathString)
        return command
    }

    // These supplemental evidence tools are explicit policy, never a silent compiler fallback.
    // Front-end diagnostics run at -O0: Clang 23 suppresses -Wformat-security when optimizing.
    override fun diagnosticCommand(source: Path, vulnerabilityCase: MvpVulnerabilityCase): List<String> = when (vulnerabilityCase) {
        MvpVulnerabilityCase.FORMAT_STRING -> listOf("clang", "-std=c11", "-O0", "-g", "-fsyntax-only", "-Wformat", "-Wformat-security", "-Werror=format-security", source.pathString)
        MvpVulnerabilityCase.UNINITIALIZED_MEMORY -> listOf("clang", "-std=c11", "-O0", "-g", "-fsyntax-only", "-Werror=uninitialized", "-Werror=sometimes-uninitialized", source.pathString)
        else -> throw IllegalArgumentException("selected vulnerability case does not use compiler diagnostic evidence")
    }
}
