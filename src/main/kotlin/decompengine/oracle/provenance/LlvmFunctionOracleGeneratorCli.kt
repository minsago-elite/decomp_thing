package decompengine.oracle.provenance

import java.nio.file.Path
import kotlin.system.exitProcess

/**
 * Narrow Kotlin/JVM entry point for authoritative LLVM function-oracle generation.
 *
 * The CLI accepts only the four raw paths accepted by [LlvmFunctionOracleGenerator]. Selectors,
 * limits, schemas, parsed facts, authority tokens, and ACP messages remain closed implementation
 * policy and cannot enter through this surface.
 */
internal object LlvmFunctionOracleGeneratorCli {
    @JvmStatic
    fun main(arguments: Array<String>) {
        exitProcess(run(arguments))
    }

    internal fun run(
        arguments: Array<String>,
        stdout: (String) -> Unit = ::println,
        stderr: (String) -> Unit = System.err::println,
    ): Int = try {
        val options = LlvmFunctionOracleCliArguments.parse(arguments)
        val result = LlvmFunctionOracleGenerator.generate(
            manifestPath = options.manifest,
            exclusionsPath = options.exclusions,
            artifactRoot = options.artifactRoot,
            outputPath = options.output,
        )
        stdout("generated LLVM function oracle: ${result.outputPath}")
        stdout(
            "  ${result.functions} functions, ${result.exclusions} exclusions, " +
                "${result.outputBytes} bytes, sha256:${result.outputSha256}",
        )
        0
    } catch (failure: Exception) {
        stderr("LLVM function-oracle generation failed: ${failure.message}")
        1
    }
}

private data class LlvmFunctionOracleCliArguments(
    val manifest: Path,
    val exclusions: Path,
    val artifactRoot: Path,
    val output: Path,
) {
    companion object {
        fun parse(arguments: Array<String>): LlvmFunctionOracleCliArguments {
            if (arguments.size % 2 != 0) {
                functionOracleCliFail("options must be --name path pairs")
            }
            val values = linkedMapOf<String, String>()
            arguments.asList().chunked(2).forEach { (rawName, value) ->
                if (!rawName.matches(OPTION_NAME)) {
                    functionOracleCliFail("invalid option name $rawName")
                }
                val name = rawName.removePrefix("--")
                if (name !in REQUIRED_OPTIONS) functionOracleCliFail("unknown option $rawName")
                if (value.isEmpty()) functionOracleCliFail("$rawName requires a non-empty path")
                if (values.put(name, value) != null) functionOracleCliFail("duplicate option $rawName")
            }
            val missing = REQUIRED_OPTIONS.firstOrNull { it !in values }
            if (missing != null) functionOracleCliFail("missing required --$missing")
            return LlvmFunctionOracleCliArguments(
                manifest = Path.of(values.getValue("manifest")),
                exclusions = Path.of(values.getValue("exclusions")),
                artifactRoot = Path.of(values.getValue("artifact-root")),
                output = Path.of(values.getValue("output")),
            )
        }

        private val REQUIRED_OPTIONS = linkedSetOf("manifest", "exclusions", "artifact-root", "output")
        private val OPTION_NAME = Regex("--[a-z][a-z-]*")
    }
}

private fun functionOracleCliFail(message: String): Nothing =
    throw LlvmFunctionOracleGenerationException(message)
