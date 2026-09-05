package decompengine.mvp

import decompengine.analysis.fakeGhidraCommand
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.pathString
import kotlin.io.path.readText
import kotlin.io.path.writeBytes
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class GhidraDecompilerTest {
    @Test
    fun `adapter invokes headless Ghidra with only the ELF and bundled script`() {
        val temp = createTempDirectory("ghidra-adapter-")
        val home = temp.resolve("ghidra")
        val executable = home.resolve("fake-worker")
        executable.parent.createDirectories()
        executable.writeText(
            """
            #!/bin/sh
            printf '%s\n' "${'$'}@" > "${'$'}PWD/invocation.txt"
            for last do :; done
            printf '/* GHIDRA_PROGRAM_CONTEXT */\nint main(void) { return 0; }\n' > "${'$'}last"
            printf 'headless analysis progress\n'
            printf 'headless diagnostic\n' >&2
            """.trimIndent() + "\n",
        )
        executable.toFile().setExecutable(true)
        val input = temp.resolve("input/program.elf")
        input.parent.createDirectories()
        input.writeBytes(byteArrayOf(0x7f, 0x45, 0x4c, 0x46))
        val work = temp.resolve("work").createDirectories()
        val raw = work.resolve("decompiled.c")
        val log = temp.resolve("logs/ghidra.log")
        log.parent.createDirectories()

        StreamingLogger(log).use { logger ->
            GhidraDecompiler(fakeGhidraCommand(executable)).decompile(logger, input, work, raw)
        }

        val invocation = work.resolve("invocation.txt").readText()
        assertTrue(invocation.contains("-import\n${input.toAbsolutePath()}"))
        assertTrue(invocation.contains("-postScript\nExportDecompiledC.java"))
        assertTrue(invocation.endsWith("${raw.toAbsolutePath()}\n"))
        assertFalse(invocation.contains("benchmarks/fixtures"))
        assertTrue(work.resolve("ghidra_scripts/ExportDecompiledC.java").readText().contains("GHIDRA_DEFINED_STRINGS"))
        assertTrue(raw.readText().contains("GHIDRA_PROGRAM_CONTEXT"))
        assertTrue(log.readText().contains("headless analysis progress"))
        assertTrue(log.readText().contains("headless diagnostic"))
    }

    @Test
    fun `opt in real Ghidra exports symbol type string and control flow context`() {
        if (System.getenv("RUN_REAL_GHIDRA") != "true") return
        val temp = createTempDirectory("ghidra-real-")
        val source = temp.resolve("program.c")
        val binary = temp.resolve("program")
        source.writeText("#include <stdio.h>\nstatic int twice(int x) { return x * 2; }\nint main(void) { puts(\"oracle-string\"); return twice(0); }\n")
        val compiler = ProcessBuilder("gcc", "-g", "-O0", source.pathString, "-o", binary.pathString)
            .redirectErrorStream(true).start()
        val compilerOutput = compiler.inputStream.bufferedReader().readText()
        check(compiler.waitFor() == 0) { compilerOutput }
        source.toFile().delete()
        val work = temp.resolve("work").createDirectories()
        val raw = work.resolve("decompiled.c")

        StreamingLogger(temp.resolve("ghidra.log")).use { logger ->
            GhidraDecompiler().decompile(logger, binary, work, raw)
        }

        val result = raw.readText()
        assertTrue(result.contains("GHIDRA_PROGRAM_CONTEXT"))
        assertTrue(result.contains("GHIDRA_SYMBOLS"))
        assertTrue(result.contains("GHIDRA_DEFINED_STRINGS"))
        assertTrue(result.contains("oracle-string"))
        assertTrue(result.contains("signature:"))
        assertTrue(result.contains("instruction-count:"))
        assertTrue(result.contains("control-flow-edges:"))
    }
}
