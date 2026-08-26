package decompengine.mvp

import decompengine.repair.RepairClient
import decompengine.repair.RepairRequest
import decompengine.repair.RepairResponse
import decompengine.repair.SourcePatch
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.pathString
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class MvpPatchWorkflowTest {
    @Test
    fun `runs patch workflow and publishes verified artifacts`() {
        val tempDir = createTempDirectory("mvp-patch-")
        val input = compileC(tempDir, "original", originalSource())
        val output = tempDir.resolve("output")
        output.resolve("stale/nested").createDirectories()
        output.resolve("stale/nested/old.txt").writeText("old output")
        val client = QueueRepairClient(
            RepairResponse("reconstruct vulnerable source", listOf(SourcePatch("decompiled.c", vulnerableSource()))),
            RepairResponse("bound copy to the local buffer without exposing top-secret-value", listOf(SourcePatch("patched.c", patchedSource()))),
        )

        MvpPatchWorkflow(
            client = client,
            environment = mapOf("API_KEY" to "top-secret-value"),
            approve = { true },
            decompiler = BinaryDecompiler { _, _, _, raw -> raw.writeText("int main(void) { /* ghidra */ }\n") },
            binaryExecution = testExecutionBoundary(),
        ).run(MvpPatchOptions(input, output))

        assertEquals(2, client.requests.size)
        assertTrue(client.requests.first().projectFiles.keys.single().endsWith("ghidra_decompiled.c"))
        assertTrue(client.requests.first().projectFiles.values.single().contains("ghidra"))
        assertTrue(output.resolve("decompile/decompiled.c").readText().contains("badge[i]"))
        assertFalse(output.resolve("stale/nested/old.txt").exists())
        assertTrue(output.resolve("patched_c/patched.c").readText().contains("return 0;"))
        assertTrue(output.resolve("patched_binary/patched_binary").exists())
        val summary = output.resolve("summary/SUMMARY.md").readText()
        assertTrue(summary.contains("Result: PASS"))
        assertTrue(summary.contains("## CWE-787 Evidence and Source Mapping"))
        assertTrue(summary.contains("decompiled.c:"))
        assertTrue(summary.contains("## Approved Source Change"))
        assertTrue(summary.contains("bound copy to the local buffer"))
        assertFalse(summary.contains("top-secret-value"))
        assertTrue(summary.contains("[REDACTED]"))
        assertTrue(summary.contains("approved interactively"))
        assertTrue(summary.contains("| verify | PASS |"))
        assertTrue(summary.contains("binary hardening inspection | PASS"))
        assertTrue(summary.contains("behavior validation | PASS"))
        assertTrue(summary.contains("evidence/approved.patch"))
        assertTrue(output.resolve("evidence/approved.patch").exists())
        assertTrue(output.resolve("evidence/cwe-787-sanitizer.txt").exists())
        assertTrue(output.resolve("evidence/reconstruction-request.md").readText().contains("Binary-derived context"))
        assertTrue(output.resolve("evidence/reconstruction-response.md").readText().contains("badge[i]"))
        assertTrue(output.resolve("evidence/patch-request.md").readText().contains("Sanitizer evidence"))
        assertTrue(output.resolve("evidence/patch-response.md").readText().contains("[REDACTED]"))
        assertTrue(Regex("`[0-9a-f]{64}`").containsMatchIn(summary))

        val patched = ProcessBuilder(output.resolve("patched_binary/patched_binary").pathString).start()
        assertEquals(0, patched.waitFor())
        assertEquals("[03] Alexandria Stone\n", patched.inputStream.bufferedReader().readText())
    }

    @Test
    fun `does not publish binary when patch is not approved`() {
        val tempDir = createTempDirectory("mvp-reject-")
        val input = compileC(tempDir, "original", originalSource())
        val output = tempDir.resolve("output")
        val client = QueueRepairClient(
            RepairResponse("reconstruct vulnerable source", listOf(SourcePatch("decompiled.c", vulnerableSource()))),
            RepairResponse("bound copy to the local buffer", listOf(SourcePatch("patched.c", patchedSource()))),
        )

        val failure = assertFailsWith<MvpPatchException> {
            MvpPatchWorkflow(
                client = client,
                approve = { false },
                decompiler = BinaryDecompiler { _, _, _, raw -> raw.writeText("decompiled c") },
                binaryExecution = testExecutionBoundary(),
            ).run(MvpPatchOptions(input, output))
        }

        assertTrue(failure.message.orEmpty().contains("not approved"))
        assertFalse(output.resolve("patched_binary/patched_binary").exists())
        val summary = output.resolve("summary/SUMMARY.md").readText()
        assertTrue(summary.contains("Result: FAIL"))
        assertTrue(summary.contains("Failure phase and reason: patch: patch was not approved"))
        assertTrue(summary.contains("rejected interactively"))
        assertTrue(summary.contains("Verified final binary: `not published`"))
    }

    @Test
    fun `rejects non ELF input before decompilation`() {
        val tempDir = createTempDirectory("mvp-invalid-")
        val input = tempDir.resolve("not-elf")
        input.writeText("not an elf")
        val output = tempDir.resolve("output")

        val failure = assertFailsWith<MvpPatchException> {
            MvpPatchWorkflow(
                client = QueueRepairClient(),
                decompiler = BinaryDecompiler { _, _, _, _ -> error("must not run") },
                binaryExecution = testExecutionBoundary(),
            ).run(MvpPatchOptions(input, output, assumeYes = true))
        }

        assertTrue(failure.message.orEmpty().contains("64-bit ELF"))
        assertFalse(output.resolve("patched_binary/patched_binary").exists())
    }

    @Test
    fun `yes automation records approval without prompting`() {
        val tempDir = createTempDirectory("mvp-yes-")
        val input = compileC(tempDir, "original", originalSource())
        val output = tempDir.resolve("output")
        val client = QueueRepairClient(
            RepairResponse("reconstruct vulnerable source", listOf(SourcePatch("decompiled.c", vulnerableSource()))),
            RepairResponse("bound copy", listOf(SourcePatch("patched.c", patchedSource()))),
        )

        MvpPatchWorkflow(
            client = client,
            approve = { error("--yes must bypass the interactive prompt") },
            decompiler = BinaryDecompiler { _, _, _, raw -> raw.writeText("decompiled c") },
            binaryExecution = testExecutionBoundary(),
        ).run(MvpPatchOptions(input, output, assumeYes = true))

        assertTrue(output.resolve("summary/SUMMARY.md").readText().contains("approved by --yes automation"))
    }

    @Test
    fun `rejects placeholder reconstruction before compilation`() {
        val tempDir = createTempDirectory("mvp-placeholder-")
        val input = compileC(tempDir, "original", originalSource())
        val output = tempDir.resolve("output")
        val client = QueueRepairClient(
            RepairResponse("placeholder", listOf(SourcePatch("decompiled.c", "int main(void) { return 0; }\n"))),
        )

        val failure = assertFailsWith<MvpPatchException> {
            MvpPatchWorkflow(
                client = client,
                decompiler = BinaryDecompiler { _, _, _, raw -> raw.writeText("binary-derived ghidra context") },
                binaryExecution = testExecutionBoundary(),
            ).run(MvpPatchOptions(input, output, assumeYes = true))
        }

        assertTrue(failure.message.orEmpty().contains("placeholder"))
        assertFalse(output.resolve("patched_binary/patched_binary").exists())
        assertTrue(output.resolve("evidence/reconstruction-request.md").exists())
        assertTrue(output.resolve("evidence/reconstruction-response.md").exists())
    }

    @Test
    fun `allows top level docker output mount`() {
        val output = Path.of("/output")
        val input = Path.of("/input/binary_01")

        assertTrue(output.root != null)
        assertTrue(output != output.root)
        assertTrue(output != input.parent)
    }

    private class QueueRepairClient(vararg responses: RepairResponse) : RepairClient {
        private val responses = ArrayDeque(responses.toList())
        val requests = mutableListOf<RepairRequest>()

        override fun requestRepair(request: RepairRequest): RepairResponse {
            requests += request
            return responses.removeFirst()
        }
    }

    private fun testExecutionBoundary() = BinaryExecutionBoundary { executable, directory, environment ->
        val process = ProcessBuilder(executable.toAbsolutePath().toString())
            .directory(directory.toFile())
            .apply { environment().putAll(environment) }
            .start()
        BinaryExecutionResult(
            process.waitFor(),
            process.inputStream.bufferedReader().readText(),
            process.errorStream.bufferedReader().readText(),
            BinaryIsolation("deterministic test boundary", networkIsolated = true, credentialsIsolated = true),
        )
    }

    private fun compileC(tempDir: Path, name: String, source: String): Path {
        val sourcePath = tempDir.resolve("$name.c")
        val binary = tempDir.resolve(name)
        sourcePath.writeText(source)
        val process = ProcessBuilder("gcc", "-std=c11", "-Wall", "-Wextra", "-Werror", sourcePath.pathString, "-o", binary.pathString)
            .redirectErrorStream(true)
            .start()
        val output = process.inputStream.bufferedReader().readText()
        check(process.waitFor() == 0) { output }
        return binary
    }

    private fun originalSource() = """
        #include <stdio.h>
        int main(void) {
            puts("[03] Alexandria Stone");
            return 0;
        }
    """.trimIndent()

    private fun vulnerableSource() = """
        #include <stdio.h>
        int main(void) {
            char badge[8];
            const char *message = "[03] Alexandria Stone";
            for (volatile int i = 0; message[i] != '\0'; i++) {
                badge[i] = message[i];
            }
            puts("[03] Alexandria Stone");
            return badge[0] == 0;
        }
    """.trimIndent() + "\n"

    private fun patchedSource() = """
        #include <stdio.h>
        int main(void) {
            puts("[03] Alexandria Stone");
            return 0;
        }
    """.trimIndent() + "\n"
}
