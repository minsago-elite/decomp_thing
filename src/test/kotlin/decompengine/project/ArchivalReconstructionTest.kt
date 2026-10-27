package decompengine.project

import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.readText
import kotlin.io.path.writeBytes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ArchivalReconstructionTest {
    @Test
    fun `incomplete agent reconstruction preserves reports without building placeholders`() {
        val temp = createTempDirectory("archival-incomplete-")
        val binary = temp.resolve("input.elf").also { it.writeBytes(byteArrayOf(1)) }
        val analyzer = ProgramModelAnalyzer { _, _ -> RecoveredProgramModel(
            inputSha256 = "input", functions = listOf(RecoveredFunction("fn_1000", "decomp_engine_main", 0x1000UL,
                "int decomp_engine_main(void)")),
        ) }
        val harness = decompengine.agent.AgentHarness { _, _ ->
            decompengine.agent.AgentExecutionResult(decompengine.agent.AgentStopReason.NO_CHANGES)
        }
        val output = temp.resolve("result")
        val failure = kotlin.test.assertFailsWith<ReconstructionIncompleteException> {
            ArchivalReconstructionService(analyzer, BoundedLlmModuleReconstructor(harness)).reconstruct(binary, output)
        }
        assertEquals(1, failure.unresolvedModules)
        assertTrue(output.resolve("reconstruction.json").readText().contains("incomplete"))
        assertTrue(output.resolve("source-tree/UNRESOLVED.md").exists())
        kotlin.test.assertFalse(output.resolve("source-tree.zip").exists())
        kotlin.test.assertFalse(output.resolve("source-tree/build").exists())
    }

    @Test
    fun `service recovers builds and packages a complete source tree`() {
        val temp = createTempDirectory("archival-service-")
        val binary = temp.resolve("input.elf").also { it.writeBytes(byteArrayOf(1, 2, 3)) }
        val analyzer = ProgramModelAnalyzer { supplied, work ->
            assertEquals(binary, supplied)
            assertTrue(work.toString().endsWith("analysis"))
            RecoveredProgramModel(
                inputSha256 = sha256(supplied.toFile().readBytes()),
                functions = listOf(RecoveredFunction("fn_1000", "decomp_engine_main", 0x1000UL, "int decomp_engine_main(void)")),
            )
        }

        val result = ArchivalReconstructionService(analyzer).reconstruct(binary, temp.resolve("result"))

        assertEquals(0, result.build.returnCode)
        assertTrue(result.projectDir.resolve("src/modules/decomp.c").exists())
        assertTrue(result.bundle.archivePath.exists())
        assertTrue(temp.resolve("result/reconstruction.json").readText().contains(result.bundle.archiveSha256))
    }
}
