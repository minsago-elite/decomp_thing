package decompengine.project

import decompengine.analysis.GhidraAnalysisException
import java.nio.file.Path
import java.time.Duration
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.deleteExisting
import kotlin.io.path.listDirectoryEntries
import kotlin.io.path.pathString
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class GhidraProgramModelExporterTest {
    @Test
    fun `headless adapter installs the staged exporter and reads its final model`() {
        val temp = createTempDirectory("program-model-adapter-")
        val home = fakeGhidraHome(temp, complete = true)
        val binary = temp.resolve("input/program").also {
            it.parent.createDirectories()
            it.writeText("binary fixture")
        }
        val work = temp.resolve("analysis")

        val model = GhidraHeadlessProgramModelAnalyzer(home).analyze(binary, work)

        assertEquals("fake-input", model.inputSha256)
        assertEquals(listOf("fn_0000000000001000"), model.functions.map { it.id })
        val invocation = work.resolve("invocation.txt").readText()
        assertTrue(invocation.contains("-postScript\nExportProgramModel.java"))
        assertTrue(invocation.endsWith("${work.resolve("reports/program_model.json").toAbsolutePath()}\n"))
        val exporter = work.resolve("scripts/ExportProgramModel.java").readText()
        assertTrue(exporter.contains("program-model export complete"))
        assertTrue(exporter.contains("writeIfAbsentAtomic"))
        assertTrue(exporter.contains("if (isAcceptedRecord(record)) continue"))
        assertTrue(exporter.contains("Files.copy(records.get(index), output)"))
        assertTrue(exporter.contains("DECOMPILE_TIMEOUT_SECONDS = 60"))
    }

    @Test
    fun `headless adapter terminates an over-budget export with resumable guidance`() {
        val temp = createTempDirectory("program-model-timeout-")
        val home = fakeGhidraHome(temp, complete = false)
        val binary = temp.resolve("input/program").also {
            it.parent.createDirectories()
            it.writeText("binary fixture")
        }
        val work = temp.resolve("analysis")
        val analyzer = GhidraHeadlessProgramModelAnalyzer(
            home,
            GhidraProgramModelExportLimits(Duration.ofMillis(500), Duration.ofMillis(100)),
        )

        val failure = assertFailsWith<GhidraAnalysisException> { analyzer.analyze(binary, work) }

        assertTrue(failure.message.orEmpty().contains("rerun with the same output directory"))
        assertTrue(work.resolve("reports/ghidra_stdout.log").readText().contains("fake export started"))
    }

    @Test
    fun `opt in real Ghidra reuses accepted function records deterministically`() {
        if (System.getenv("RUN_REAL_GHIDRA") != "true") return
        val home = System.getenv("GHIDRA_HOME")?.let(Path::of)
            ?: error("RUN_REAL_GHIDRA=true requires GHIDRA_HOME")
        val temp = createTempDirectory("program-model-real-")
        val source = temp.resolve("program.c")
        val binary = temp.resolve("program")
        source.writeText(
            "#include <stdio.h>\nstatic int twice(int x) { return x * 2; }\n" +
                "int main(void) { puts(\"resumable-export\"); return twice(0); }\n",
        )
        val compiler = ProcessBuilder("gcc", "-g", "-O0", source.pathString, "-o", binary.pathString)
            .redirectErrorStream(true)
            .start()
        val compilerOutput = compiler.inputStream.bufferedReader().readText()
        check(compiler.waitFor() == 0) { compilerOutput }
        source.deleteExisting()
        val work = temp.resolve("analysis")
        val analyzer = GhidraHeadlessProgramModelAnalyzer(home)

        val first = analyzer.analyze(binary, work)
        val modelPath = work.resolve("reports/program_model.json")
        val firstModel = modelPath.readBytes()
        val records = modelPath.resolveSibling("program_model.json.export/functions").listDirectoryEntries("*.json").sorted()
        assertTrue(records.isNotEmpty())
        val firstRecords = records.associateWith { it.readBytes() }
        modelPath.deleteExisting()
        records.last().deleteExisting()

        val resumed = analyzer.analyze(binary, work)

        assertEquals(first, resumed)
        assertTrue(firstModel.contentEquals(modelPath.readBytes()))
        firstRecords.forEach { (path, bytes) -> assertTrue(bytes.contentEquals(path.readBytes()), path.pathString) }
        val progress = modelPath.resolveSibling("program_model.json.progress.json").readText()
        assertTrue(progress.contains("\"phase\":\"complete\""))
        assertTrue(progress.contains("\"reused\":${records.size - 1}"), progress)
        assertTrue(work.resolve("reports/ghidra_stdout.log").readText().contains("reused=${records.size - 1}"))
    }

    private fun fakeGhidraHome(temp: Path, complete: Boolean): Path {
        val home = temp.resolve(if (complete) "fake-ghidra" else "slow-ghidra")
        val executable = home.resolve("support/analyzeHeadless")
        executable.parent.createDirectories()
        executable.writeText(
            if (complete) {
                """
                #!/bin/sh
                printf '%s\n' "${'$'}@" > "${'$'}PWD/invocation.txt"
                for last do :; done
                printf '%s\n' '{"schemaVersion":1,"inputSha256":"fake-input","functions":[{"id":"fn_0000000000001000","name":"main","address":"0x1000","prototype":"int main(void)","status":"recovered","calls":[],"referencedGlobals":[],"strings":[],"decompiledC":null}],"globals":[],"types":[]}' > "${'$'}last"
                """.trimIndent() + "\n"
            } else {
                """
                #!/bin/sh
                printf 'fake export started\n'
                while :; do :; done
                """.trimIndent() + "\n"
            },
        )
        executable.toFile().setExecutable(true)
        return home
    }
}
