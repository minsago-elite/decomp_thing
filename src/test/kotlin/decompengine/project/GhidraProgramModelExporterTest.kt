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
        assertTrue(invocation.lineSequence().any { it.matches(Regex("[0-9a-f]{64}")) })
        assertTrue(invocation.endsWith("${work.resolve("reports/program_model.json").toAbsolutePath()}\n"))
        val exporter = work.resolve("scripts/ExportProgramModel.java").readText()
        assertTrue(exporter.contains("program-model export complete"))
        assertTrue(exporter.contains("writeIfAbsentAtomic"))
        assertTrue(exporter.contains("if (isAcceptedRecord(record)) continue"))
        assertTrue(exporter.contains("copyBoundFragment"))
        assertTrue(exporter.contains("DECOMPILE_TIMEOUT_SECONDS = 60"))
        assertTrue(exporter.contains("exporterSha256"))
        assertTrue(exporter.contains("analysisToolSha256"))
        assertTrue(exporter.contains("recoveryMode"))
        assertTrue(exporter.contains("PLANNING_BATCH_FUNCTIONS = 512"))
        assertTrue(exporter.contains("validatePlanningBatchPair"))
        assertTrue(exporter.contains("planning-batches"))
        assertTrue(exporter.contains(".functions.fragment"))
        assertTrue(exporter.contains(".globals.fragment"))
        assertTrue(exporter.contains(".types.fragment"))
        assertTrue(exporter.contains(".failures.fragment"))
        assertTrue(exporter.contains("stateSha256"))
        assertTrue(exporter.contains("inventorySha256"))
        assertTrue(exporter.contains("writePlanningAtomic"))
        assertTrue(exporter.contains("MAXIMUM_PLANNING_BATCHES = 256"))
        assertTrue(exporter.contains("MAXIMUM_PROGRAM_MODEL_BYTES = 512L * 1024 * 1024"))
        assertTrue(exporter.contains("BoundedOutput"))
        assertTrue(exporter.contains("ExporterSemanticFingerprintV1"))
        assertTrue(exporter.contains("MAXIMUM_CANONICAL_BYTES = 1024L * 1024 * 1024"))
        assertTrue(exporter.contains("semanticStateBinding"))
        assertTrue(exporter.contains("batchCommitmentSha256"))
        assertTrue(exporter.contains("planning-exporter-visible-program"))
        assertTrue(exporter.contains("legacy export state schema 1 has no whole-program semantic binding"))
        assertTrue(exporter.contains("exportFunction(function, null, null, null, evidence, false)"))
        assertTrue(exporter.contains("Set<String> ownedGlobalIds = new TreeSet<>()"))
        assertTrue(exporter.contains("Set<String> ownedTypeIds = new TreeSet<>()"))
        assertTrue(exporter.contains("new PlanningBatchEvidence(ownedGlobalIds, ownedTypeIds)"))
        assertTrue(exporter.contains("ownedGlobalIds.add(global.getKey())"))
        assertTrue(exporter.contains("ownedTypeIds.add(type.getKey())"))
        assertTrue(exporter.contains("fingerprint.observeGlobal(global.getKey(), global.getValue())"))
        assertTrue(exporter.contains("fingerprint.observeType(type.getKey(), type.getValue())"))
        assertTrue(exporter.contains("fingerprint.observeFailure(id, failure)"))
        assertTrue(exporter.contains("expectedPlanningBatch(planningSemanticState, start, end)"))
        assertTrue(exporter.contains("requirePlanningBatchMatchesSemanticState(expectedBatch, validation)"))
        assertTrue(
            Regex("requirePlanningBatchMatchesSemanticState\\(expectedBatch, validation\\)")
                .findAll(exporter).count() >= 3,
        )
        val generatedCommitment = exporter.lastIndexOf("ExporterSemanticFingerprintV1.commitBatch(\n                        start")
        val firstFragmentWrite = exporter.lastIndexOf("writePlanningAtomic(functionFragmentPath, functionFragmentText)")
        assertTrue(generatedCommitment >= 0 && generatedCommitment < firstFragmentWrite)
        val planningBranch = exporter.substring(exporter.indexOf("discardPlanningPendingFiles(planningBatchesDirectory, total)"))
        val reuseValidation = planningBranch.indexOf("PlanningBatchValidation validation = validatePlanningBatchPair(")
        val reuseCommitment = planningBranch.indexOf(
            "requirePlanningBatchMatchesSemanticState(expectedBatch, validation)",
            reuseValidation,
        )
        val reuseCount = planningBranch.indexOf("completed = end", reuseCommitment)
        assertTrue(reuseValidation >= 0 && reuseValidation < reuseCommitment && reuseCommitment < reuseCount)
        val durableValidation = planningBranch.lastIndexOf("validation = validatePlanningBatchPair(")
        val durableCommitment = planningBranch.indexOf(
            "requirePlanningBatchMatchesSemanticState(expectedBatch, validation)",
            durableValidation,
        )
        val durableOwnership = planningBranch.indexOf("ownedGlobalIds.add(id)", durableCommitment)
        assertTrue(durableValidation >= 0 && durableValidation < durableCommitment && durableCommitment < durableOwnership)
        val semanticPreflight = exporter.lastIndexOf("computePlanningSemanticState(functions)")
        val stateAcceptance = exporter.lastIndexOf("ExporterSemanticFingerprintV1.requireReusableState(existing, state)")
        val batchReuse = exporter.lastIndexOf("discardPlanningPendingFiles(planningBatchesDirectory, total)")
        assertTrue(semanticPreflight >= 0 && semanticPreflight < stateAcceptance)
        assertTrue(stateAcceptance < batchReuse)
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
    fun `headless adapter rejects a program model beyond its parser byte bound`() {
        val temp = createTempDirectory("program-model-bound-")
        val home = fakeGhidraHome(temp, complete = true)
        val binary = temp.resolve("input/program").also {
            it.parent.createDirectories()
            it.writeText("binary fixture")
        }

        val analyzer = GhidraHeadlessProgramModelAnalyzer(
            home,
            GhidraProgramModelExportLimits(maximumProgramModelBytes = 16),
        )

        assertFailsWith<IllegalArgumentException> { analyzer.analyze(binary, temp.resolve("analysis")) }
    }

    @Test
    fun `export timeout is supplied by the authenticated reconstruction profile`() {
        val profile = GeneratedCMakeReconstructionProfile.descriptor

        val limits = GhidraProgramModelExportLimits.from(profile)

        assertEquals(profile.budgets.exportWallClockMillis, limits.wallClockTimeout.toMillis())
        assertEquals(profile.budgets.exportMaximumResidentBytes, limits.maximumResidentBytes)
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

    @Test
    fun `opt in real Ghidra reuses authenticated planning batches deterministically`() {
        if (System.getenv("RUN_REAL_GHIDRA") != "true") return
        val home = System.getenv("GHIDRA_HOME")?.let(Path::of)
            ?: error("RUN_REAL_GHIDRA=true requires GHIDRA_HOME")
        val temp = createTempDirectory("program-model-planning-real-")
        val source = temp.resolve("program.c")
        val binary = temp.resolve("program")
        source.writeText(
            "static int twice(int x) { return x * 2; }\n" +
                "int main(void) { return twice(21); }\n",
        )
        val compiler = ProcessBuilder("gcc", "-g", "-O0", source.pathString, "-o", binary.pathString)
            .redirectErrorStream(true)
            .start()
        val compilerOutput = compiler.inputStream.bufferedReader().readText()
        check(compiler.waitFor() == 0) { compilerOutput }
        source.deleteExisting()
        val work = temp.resolve("analysis")
        val analyzer = GhidraHeadlessProgramModelAnalyzer(
            home,
            recoveryMode = GhidraProgramModelRecoveryMode.PLANNING,
        )

        val first = analyzer.analyze(binary, work)
        val modelPath = work.resolve("reports/program_model.json")
        val firstModel = modelPath.readBytes()
        val batches = modelPath.resolveSibling("program_model.json.export/planning-batches")
        val checkpoints = batches.listDirectoryEntries("*.checkpoint")
        assertTrue(checkpoints.isNotEmpty())

        val resumed = analyzer.analyze(binary, work)

        assertEquals(first, resumed)
        assertTrue(firstModel.contentEquals(modelPath.readBytes()))
        val progress = modelPath.resolveSibling("program_model.json.progress.json").readText()
        assertTrue(progress.contains("\"phase\":\"complete\""))
        assertTrue(progress.contains("\"reused\":${first.functions.size}"), progress)
    }

    private fun fakeGhidraHome(temp: Path, complete: Boolean): Path {
        val home = temp.resolve(if (complete) "fake-ghidra" else "slow-ghidra")
        val executable = home.resolve("support/analyzeHeadless")
        executable.parent.createDirectories()
        val canonicalModel = home.resolve("canonical-program-model.json")
        if (complete) {
            canonicalModel.writeText(
                RecoveredProgramModel(
                    inputSha256 = "fake-input",
                    functions = listOf(
                        RecoveredFunction(
                            id = "fn_0000000000001000",
                            name = "main",
                            address = 0x1000UL,
                            prototype = "int main(void)",
                        ),
                    ),
                ).toJson(),
            )
        }
        executable.writeText(
            if (complete) {
                """
                #!/bin/sh
                printf '%s\n' "${'$'}@" > "${'$'}PWD/invocation.txt"
                for last do :; done
                cp '${canonicalModel.pathString}' "${'$'}last"
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
