package decompengine.integration

import kotlin.io.path.Path
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.pathString
import kotlin.test.Test
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class CVulFixtureIntegrationTest {
    @Test
    fun `01 out of bounds write reproduces under address sanitizer`() {
        val source = Path("benchmarks/fixtures/c-vul/src/01_out_of_bounds_write.c")
        assertTrue(source.exists(), "initialize the c-vul submodule before running tests")
        val binary = createTempDirectory("c-vul-01-").resolve("binary_01_asan")

        val compiler = ProcessBuilder(
            "gcc",
            "-std=c11",
            "-O0",
            "-g",
            "-fsanitize=address,undefined",
            "-fno-omit-frame-pointer",
            source.pathString,
            "-o",
            binary.pathString,
        ).redirectErrorStream(true).start()
        val compilerOutput = compiler.inputStream.bufferedReader().readText()
        check(compiler.waitFor() == 0) { "gcc failed: $compilerOutput" }

        val reproducer = ProcessBuilder(binary.pathString)
            .redirectErrorStream(true)
            .apply { environment()["ASAN_OPTIONS"] = "detect_leaks=0:halt_on_error=1" }
            .start()
        val reproducerOutput = reproducer.inputStream.bufferedReader().readText()
        val exitCode = reproducer.waitFor()

        assertNotEquals(0, exitCode)
        assertTrue(reproducerOutput.contains("AddressSanitizer: stack-buffer-overflow"), reproducerOutput)
        assertTrue(reproducerOutput.contains("01_out_of_bounds_write.c"), reproducerOutput)
    }
}
