package decompengine.mvp

import decompengine.repair.RepairClient
import decompengine.repair.RepairClientAgentHarness
import decompengine.repair.RepairClientInvocation
import decompengine.repair.RepairRequest
import decompengine.repair.RepairResponse
import decompengine.repair.SourcePatch
import java.nio.file.Path
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.pathString
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** Actual compiler/workflow controls with authored candidates; never live agent qualification. */
class MvpTenCaseWorkflowTest {
    @Test
    fun `all ten authored candidate repairs pass their real workflow checks without release authority`() {
        val filenames = listOf("01_out_of_bounds_write.c", "02_out_of_bounds_read.c", "03_use_after_free.c",
            "04_double_invalid_free.c", "05_format_string.c", "06_integer_overflow.c", "07_null_pointer_deref.c",
            "08_uninitialized_memory.c", "09_memory_leak.c", "10_command_injection.c")
        val completed = mutableSetOf<String>()
        for ((case, filename) in MvpVulnerabilityCase.entries.zip(filenames)) {
            val temp = createTempDirectory("mvp-case-${case.id}-")
            val vulnerable = Path.of("benchmarks/fixtures/c-vul/src/$filename").readText()
            val correctedPath = Path.of("benchmarks/fixtures/c-vul-repaired/$filename").toAbsolutePath()
            val corrected = correctedPath.readText()
            val input = temp.resolve("original")
            val compiler = ProcessBuilder("gcc", "-std=c11", correctedPath.pathString, "-o", input.pathString)
                .redirectErrorStream(true).start()
            val compilerOutput = compiler.inputStream.bufferedReader().readText()
            assertEquals(0, compiler.waitFor(), compilerOutput)
            var requests = 0
            val client = object : RepairClient {
                override fun requestRepair(request: RepairRequest, invocation: RepairClientInvocation): RepairResponse {
                    return if (requests++ == 0) RepairResponse("authored vulnerable reconstruction control",
                        listOf(SourcePatch("decompiled.c", vulnerable)))
                    else RepairResponse("authored minimal reference correction",
                        listOf(SourcePatch("patched.c", corrected)))
                }
            }
            val boundary = object : BinaryExecutionBoundary {
                override fun execute(executable: Path, workingDirectory: Path, environment: Map<String, String>) =
                    execute(executable, workingDirectory, environment, emptyList())
                override fun execute(executable: Path, workingDirectory: Path, environment: Map<String, String>, arguments: List<String>): BinaryExecutionResult {
                    validateBinaryArguments(arguments)
                    val process = ProcessBuilder(listOf("/usr/bin/timeout", "10s", executable.pathString) + arguments)
                        .directory(workingDirectory.toFile()).apply { environment().clear(); environment().putAll(environment) }.start()
                    val stdout = process.inputStream.bufferedReader().readText()
                    val stderr = process.errorStream.bufferedReader().readText()
                    return BinaryExecutionResult(process.waitFor(), stdout, stderr,
                        BinaryIsolation("authored local test boundary; not production containment evidence", true, true))
                }
            }
            val output = temp.resolve("output")
            MvpPatchWorkflow(RepairClientAgentHarness(client), environment = emptyMap(),
                decompiler = BinaryDecompiler { _, _, _, raw -> raw.writeText("authored decompiler control") },
                binaryExecution = boundary, publicationMode = MvpPublicationMode.TEST_ONLY_NON_RELEASE)
                .run(MvpPatchOptions(input, output, assumeYes = true, vulnerabilityCase = case))
            val summary = output.resolve("summary/SUMMARY.md").readText()
            assertTrue(summary.contains("Result: NON_RELEASE"), "${case.id}: $summary")
            assertTrue(summary.contains("${case.cwe} Evidence and Source Mapping"))
            assertTrue(summary.contains(case.evidenceKind))
            assertTrue(output.resolve(case.findingRelativePath).exists())
            assertFalse(output.resolve("patched_binary/patched_binary").exists())
            assertEquals(2, requests)
            completed += case.id
        }
        assertEquals((1..10).map { "%02d".format(it) }.toSet(), completed)
    }

    @Test
    fun `case admission and evidence reject wrong weakness and incomplete invocations`() {
        for (case in MvpVulnerabilityCase.entries) {
            assertEquals(case, MvpVulnerabilityCase.named(case.id))
            assertEquals(case, MvpVulnerabilityCase.named(case.cwe))
            for (status in listOf(-1, 124, 125, 126, 127, 134, 137, 139, 143, 153)) {
                assertFalse(case.matchesFinding(status, "ERROR: AddressSanitizer: stack-buffer-overflow WRITE of size 4"))
            }
            assertFalse(case.matchesFinding(1, "unrelated failure"))
        }
        assertFailsWith<IllegalArgumentException> { MvpVulnerabilityCase.named("PRIVATE_UNKNOWN") }
        val write = "ERROR: AddressSanitizer: stack-buffer-overflow WRITE of size 4"
        val read = "ERROR: AddressSanitizer: stack-buffer-overflow READ of size 4"
        assertTrue(MvpVulnerabilityCase.OUT_OF_BOUNDS_WRITE.matchesFinding(1, write))
        assertFalse(MvpVulnerabilityCase.OUT_OF_BOUNDS_READ.matchesFinding(1, write))
        assertFalse(MvpVulnerabilityCase.OUT_OF_BOUNDS_WRITE.matchesFinding(1, read))
        assertTrue(MvpVulnerabilityCase.OUT_OF_BOUNDS_READ.matchesFinding(1, read))
        assertFalse(MvpVulnerabilityCase.COMMAND_INJECTION.matchesFinding(0, "hello; printf CVUL_CANARY\n"))
    }

    @Test
    fun `leak evidence requires an admitted symbolizer and other cases keep fixed environments`() {
        val leak = MvpVulnerabilityCase.MEMORY_LEAK
        assertFailsWith<MvpPatchException> { leak.isolatedEnvironment { null } }
        val tool = Path.of("/usr/lib/llvm/23/bin/llvm-symbolizer")
        assertEquals("detect_leaks=1:halt_on_error=1:external_symbolizer_path=$tool",
            leak.isolatedEnvironment { tool }.getValue("ASAN_OPTIONS"))
        for (case in MvpVulnerabilityCase.entries - leak) {
            assertEquals(case.environment, case.isolatedEnvironment { error("non-leak cases never resolve a symbolizer") })
        }
        // A writable or out-of-bind directory is never admitted, even when first on PATH.
        val outside = createTempDirectory("symbolizer-outside-")
        outside.resolve("llvm-symbolizer").writeText("#!/bin/sh\n").also { outside.resolve("llvm-symbolizer").toFile().setExecutable(true) }
        assertEquals(null, resolveLlvmSymbolizer(outside.pathString))
        assertEquals(null, resolveLlvmSymbolizer(""))
        assertEquals(setOf("ASAN_OPTIONS"), MvpVulnerabilityCase.OUT_OF_BOUNDS_WRITE.environment.keys)
    }
}
