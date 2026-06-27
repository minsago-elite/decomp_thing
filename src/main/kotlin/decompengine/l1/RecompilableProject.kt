package decompengine.l1

import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.exists
import kotlin.io.path.pathString
import kotlin.io.path.writeText

data class BuildReport(
    val projectDir: Path,
    val returnCode: Int,
    val logPath: Path,
)

class BuildException(message: String) : RuntimeException(message)

object RecompilableProjectGenerator {
    fun generate(analysis: GhidraAnalysis, projectDir: Path): Path {
        val srcDir = projectDir.resolve("src").createDirectories()
        val includeDir = projectDir.resolve("include").createDirectories()
        val reportsDir = projectDir.resolve("reports").createDirectories()

        projectDir.resolve("Makefile").writeText(
            """
            CC ?= gcc
            CFLAGS ?= -std=c11 -Wall -Wextra -Werror -Iinclude
            TARGET ?= build/reconstructed
            SOURCES := src/main.c src/reconstructed.c

            all: ${'$'}(TARGET)

            ${'$'}(TARGET): ${'$'}(SOURCES) include/decomp_engine.h
            	@mkdir -p ${'$'}(dir ${'$'}@)
            	${'$'}(CC) ${'$'}(CFLAGS) ${'$'}(SOURCES) -o ${'$'}@

            clean:
            	rm -rf build

            .PHONY: all clean
            """.trimIndent() + "\n",
        )
        includeDir.resolve("decomp_engine.h").writeText(
            """
            #ifndef DECOMP_ENGINE_H
            #define DECOMP_ENGINE_H

            int decomp_engine_main(void);

            #endif
            """.trimIndent() + "\n",
        )
        srcDir.resolve("main.c").writeText(
            """
            #include "decomp_engine.h"

            int main(int argc, char **argv) {
                (void)argc;
                (void)argv;
                return decomp_engine_main();
            }
            """.trimIndent() + "\n",
        )
        srcDir.resolve("reconstructed.c").writeText(
            """
            #include "decomp_engine.h"

            int decomp_engine_main(void) {
                return 0;
            }
            """.trimIndent() + "\n",
        )
        reportsDir.resolve("analysis.json").writeText(
            """
            {
              "sourceAnalysis": "${analysis.reportPath.pathString}",
              "metadata": {
                "format": "${analysis.metadata.format}",
                "machine": "${analysis.metadata.machine}",
                "entryPoint": ${analysis.metadata.entryPoint}
              },
              "generatedFiles": [
                "Makefile",
                "include/decomp_engine.h",
                "src/main.c",
                "src/reconstructed.c",
                "reports/analysis.json"
              ]
            }
            """.trimIndent() + "\n",
        )
        return projectDir
    }
}

object MakeProjectBuilder {
    fun build(projectDir: Path): BuildReport {
        if (!projectDir.resolve("Makefile").exists()) {
            throw BuildException("generated project is missing Makefile")
        }
        val reportsDir = projectDir.resolve("reports").createDirectories()
        val process = ProcessBuilder("make")
            .directory(projectDir.toFile())
            .redirectErrorStream(false)
            .start()
        val stdout = process.inputStream.bufferedReader().readText()
        val stderr = process.errorStream.bufferedReader().readText()
        val returnCode = process.waitFor()
        val logPath = reportsDir.resolve("build.log")
        logPath.writeText(
            """
            ${'$'} make
            exit_code=$returnCode

            [stdout]
            $stdout
            [stderr]
            $stderr
            """.trimIndent() + "\n",
        )
        if (returnCode != 0) {
            throw BuildException("generated project failed to build; see ${logPath.pathString}")
        }
        return BuildReport(projectDir = projectDir, returnCode = returnCode, logPath = logPath)
    }
}

class L1Pipeline(private val analyzer: GhidraJvmAnalyzer) {
    fun generate(binaryPath: Path, workDir: Path): BuildReport {
        val analysis = analyzer.analyze(binaryPath, workDir.resolve("analysis"))
        val projectDir = RecompilableProjectGenerator.generate(analysis, workDir.resolve("project"))
        return MakeProjectBuilder.build(projectDir)
    }
}
