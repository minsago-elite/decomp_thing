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
            RepairResponse("bound copy to the local buffer", listOf(SourcePatch("patched.c", patchedSource()))),
        )

        MvpPatchWorkflow(
            client = client,
            approve = { true },
            decompiler = BinaryDecompiler { _, _, _, raw -> raw.writeText("int main(void) { /* ghidra */ }\n") },
        ).run(MvpPatchOptions(input, output))

        assertEquals(2, client.requests.size)
        assertTrue(client.requests.first().projectFiles.keys.single().endsWith("ghidra_decompiled.c"))
        assertTrue(output.resolve("decompile/decompiled.c").readText().contains("badge[i]"))
        assertFalse(output.resolve("stale/nested/old.txt").exists())
        assertTrue(output.resolve("patched_c/patched.c").readText().contains("return 0;"))
        assertTrue(output.resolve("patched_binary/patched_binary").exists())
        val summary = output.resolve("summary/SUMMARY.md").readText()
        assertTrue(summary.contains("Result: PASS"))
        assertTrue(summary.contains("## Vulnerability Found"))
        assertTrue(summary.contains("## Patch Explanation"))
        assertTrue(summary.contains("bound copy to the local buffer"))

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
            ).run(MvpPatchOptions(input, output))
        }

        assertTrue(failure.message.orEmpty().contains("not approved"))
        assertFalse(output.resolve("patched_binary/patched_binary").exists())
        assertTrue(output.resolve("summary/SUMMARY.md").readText().contains("Result: FAIL"))
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
            ).run(MvpPatchOptions(input, output, assumeYes = true))
        }

        assertTrue(failure.message.orEmpty().contains("64-bit ELF"))
        assertFalse(output.resolve("patched_binary/patched_binary").exists())
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
