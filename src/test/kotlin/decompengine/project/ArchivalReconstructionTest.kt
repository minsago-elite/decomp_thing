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
    fun `rejected accepted revisions restore source and receive bounded compiler corrections`() {
        for (correctable in listOf(true, false)) {
            val temp = createTempDirectory("archival-revision-correction-")
            val binary = temp.resolve("input").also { it.writeBytes(byteArrayOf(1)) }
            var changed = false
            var calls = 0
            val model = RecoveredProgramModel(inputSha256 = sha256(byteArrayOf(1)), functions = listOf(
                RecoveredFunction("fn_1000", "decomp_engine_main", 0x1000UL, "int decomp_engine_main(void)")))
            val analyzer = ProgramModelAnalyzer { _, _ ->
                if (changed) model.copy(functions = model.functions.map { it.copy(strings = setOf("new evidence")) }) else model
            }
            val output = temp.resolve("result")
            val client = object : decompengine.repair.RepairClient {
                override fun requestRepair(request: decompengine.repair.RepairRequest,
                    invocation: decompengine.repair.RepairClientInvocation): decompengine.repair.RepairResponse {
                    calls++
                    if (calls > 2) {
                        assertTrue(output.resolve("source-tree/src/modules/decomp.c").readText().contains("return 17;"))
                        assertTrue(request.prompt.contains("missing_symbol"))
                        assertTrue(request.prompt.contains("diagnostics describe the rejected candidate"))
                    }
                    val expression = if (calls == 1) "17" else if (calls > 2 && correctable) "19" else "missing_symbol"
                    return decompengine.repair.RepairResponse("candidate", listOf(decompengine.repair.SourcePatch(
                        "src/modules/decomp.c", "/* fn_1000 */\nint decomp_engine_main(void) { return $expression; }\n")))
                }
            }
            val service = ArchivalReconstructionService(analyzer,
                BoundedLlmModuleReconstructor(decompengine.repair.RepairClientAgentHarness(client)))
            service.reconstruct(binary, output)
            changed = true
            if (correctable) {
                val result = service.reconstruct(binary, output)
                assertEquals(0, result.build.returnCode)
                assertEquals(3, calls)
            } else {
                kotlin.test.assertFailsWith<ModuleReconstructionRevisionRejectedException> {
                    service.reconstruct(binary, output)
                }
                assertEquals(4, calls)
                assertTrue(output.resolve("source-tree/src/modules/decomp.c").readText().contains("return 17;"))
            }
        }
    }

    @Test
    fun `generation passes do not repeat authentication failures`() {
        val temp = createTempDirectory("archival-auth-stop-")
        val binary = temp.resolve("input.elf").also { it.writeBytes(byteArrayOf(1)) }
        val analyzer = ProgramModelAnalyzer { _, _ -> RecoveredProgramModel(
            inputSha256 = "input", functions = listOf(RecoveredFunction("fn_1000", "decomp_engine_main", 0x1000UL,
                "int decomp_engine_main(void)")),
        ) }
        var calls = 0
        val harness = decompengine.agent.AgentHarness { _, _ ->
            calls++
            throw decompengine.agent.AgentExecutionException(decompengine.agent.AgentFailure(
                decompengine.agent.AgentFailureKind.AUTHENTICATION, "private error omitted"))
        }
        kotlin.test.assertFailsWith<ReconstructionIncompleteException> {
            ArchivalReconstructionService(analyzer, BoundedLlmModuleReconstructor(harness)).reconstruct(binary, temp.resolve("result"))
        }
        assertEquals(1, calls)
    }

    @Test
    fun `bounded generation passes correct compiler failures and preserve acceptance evidence`() {
        val temp = createTempDirectory("archival-generation-retry-")
        val binary = temp.resolve("input.elf").also { it.writeBytes(byteArrayOf(1)) }
        val analyzer = ProgramModelAnalyzer { _, _ -> RecoveredProgramModel(
            inputSha256 = sha256(byteArrayOf(1)), functions = listOf(RecoveredFunction("fn_1000", "decomp_engine_main", 0x1000UL,
                "int decomp_engine_main(void)")),
        ) }
        var calls = 0
        val client = object : decompengine.repair.RepairClient {
            override fun modelIdentifier() = "fixture"
            override fun requestRepair(request: decompengine.repair.RepairRequest,
                invocation: decompengine.repair.RepairClientInvocation): decompengine.repair.RepairResponse {
                calls++
                if (calls > 1) {
                    assertTrue(request.prompt.contains("Previous candidate assessment"))
                    assertTrue(request.prompt.contains("Compiler diagnostics for the captured candidate"))
                    assertTrue(request.prompt.contains("missing_symbol"))
                }
                return decompengine.repair.RepairResponse("candidate", listOf(decompengine.repair.SourcePatch(
                    "src/modules/decomp.c", "/* fn_1000 */\nint decomp_engine_main(void) { return ${if (calls == 1) "missing_symbol" else "17"}; }\n")))
            }
        }
        val result = ArchivalReconstructionService(analyzer,
            BoundedLlmModuleReconstructor(decompengine.repair.RepairClientAgentHarness(client))).reconstruct(binary, temp.resolve("result"))
        assertEquals(2, calls)
        assertTrue(result.bundle.archivePath.exists())
        assertEquals(0, result.build.returnCode)
    }

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
