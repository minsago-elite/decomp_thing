package decompengine.project

import decompengine.analysis.BundledGhidra
import decompengine.analysis.GhidraAnalysisException
import decompengine.analysis.GhidraInvocation
import decompengine.analysis.fakeGhidraCommand
import decompengine.oracle.fulltree.inControlTemporaryDirectory
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
import java.util.concurrent.TimeUnit
import kotlinx.serialization.json.jsonObject
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.deleteExisting
import kotlin.io.path.exists
import kotlin.io.path.listDirectoryEntries
import kotlin.io.path.pathString
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class GhidraProgramModelExporterTest {
    @Test
    fun `generic owned exporter is versioned separately from the immutable profile-17 resource`() {
        val retained = checkNotNull(javaClass.getResourceAsStream("/ghidra_scripts/ExportProgramModel.java"))
            .use { it.readBytes() }
        val owned = checkNotNull(javaClass.getResourceAsStream("/ghidra_scripts/ExportProgramModelOwned.java"))
            .use { it.readBytes() }

        assertEquals("0ee91d684d310357363cbf8516b2dc65b5f56c4b38c62d4c9e09304eb3ecafaf", sha256(retained))
        assertTrue("public class ExportProgramModel extends GhidraScript" in retained.toString(Charsets.UTF_8))
        assertTrue("public class ExportProgramModelOwned extends GhidraScript" in owned.toString(Charsets.UTF_8))
        assertTrue("EXPORTER_VERSION = 19" in owned.toString(Charsets.UTF_8))
        assertTrue("owned-model-candidate-v1" in owned.toString(Charsets.UTF_8))
        assertTrue("arguments.length != 6 && arguments.length != 7" in owned.toString(Charsets.UTF_8))
        assertTrue("int protocolIndex = arguments.length == 6 ? 4 : 5" in owned.toString(Charsets.UTF_8))
        assertTrue("if (arguments.length == 7) optionalPolicy = arguments[4]" in owned.toString(Charsets.UTF_8))
        assertFalse("owned-model-candidate-v1" in retained.toString(Charsets.UTF_8))
    }

    @Test
    fun `phase diagnostics are bounded instance local partial and primary failure neutral`() {
        val exporter = checkNotNull(javaClass.getResourceAsStream("/ghidra_scripts/ExportProgramModel.java"))
            .use { it.readBytes().toString(Charsets.UTF_8) }
        val helper = exporter.substringAfter("final class ExporterPhaseObservationV1")
            .substringBefore("final class ExporterParallelCoordinatorV1")
        val root = Path.of("").toAbsolutePath().normalize().resolve("build/exporter-phase-diagnostic-tests").createDirectories()
        val directory = Files.createTempDirectory(root, "inert-")
        val source = directory.resolve("PhaseProbe.java")
        source.writeText("final class ExporterPhaseObservationV1" + helper)
        val compiler = checkNotNull(javax.tools.ToolProvider.getSystemJavaCompiler())
        assertEquals(0, compiler.run(null, null, null, "-proc:none", "-encoding", "UTF-8", "-d",
            directory.toString(), source.toString()))
        java.net.URLClassLoader(arrayOf(directory.toUri().toURL()), null).use { loader ->
            val type = loader.loadClass("ExporterPhaseObservationV1")
            val constructor = type.getDeclaredConstructor().also { it.isAccessible = true }
            val observer = constructor.newInstance()
            val phaseType = loader.loadClass("ExporterPhaseObservationV1" + '$' + "Phase")
            val phase = phaseType.enumConstants.first()
            fun method(name: String, vararg args: Class<*>) = type.getDeclaredMethod(name, *args).also { it.isAccessible = true }
            val begin = method("begin", phaseType)
            val end = method("end", phaseType, java.lang.Long.TYPE)
            val configure = method("configure", Integer.TYPE)
            val emit = method("emit", java.util.function.Consumer::class.java, Integer.TYPE,
                java.lang.Boolean.TYPE, java.lang.Boolean.TYPE)
            val lines = mutableListOf<String>()
            val sink = java.util.function.Consumer<String> { lines.add(it) }
            configure.invoke(observer, 14)
            val started = begin.invoke(observer, phase) as Long
            emit.invoke(observer, sink, 0, false, false)
            assertTrue(lines.first().contains("METADATA_INITIAL=1/0/0"), "active interval must remain in flight")
            end.invoke(observer, phase, started)
            for (completed in 1..100) emit.invoke(observer, sink, completed, false, false)
            emit.invoke(observer, sink, 100, true, false)
            emit.invoke(observer, sink, 100, true, true)
            assertEquals(64, lines.size)
            assertTrue(lines.all { it.toByteArray(Charsets.UTF_8).size <= 1024 })
            assertTrue(lines.takeLast(4).all { "state=FAILED_OR_INTERRUPTED" in it })
            assertTrue(lines.all { "clocks=elapsed_not_cpu" in it && "analyzer_cpu=UNMEASURED" in it })
            val fresh = constructor.newInstance()
            val freshLines = mutableListOf<String>()
            emit.invoke(fresh, java.util.function.Consumer<String> { freshLines.add(it) }, 0, true, true)
            assertTrue(freshLines.first().contains("METADATA_INITIAL=0/0/0"))
            // A diagnostic sink failure never escapes to replace a primary failure.
            emit.invoke(constructor.newInstance(), java.util.function.Consumer<String> { error("inert sink failure") }, 0, true, false)
        }
    }

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
        assertTrue(invocation.contains("-postScript\nExportProgramModelOwned.java"))
        assertTrue(invocation.lineSequence().any { it.matches(Regex("[0-9a-f]{64}")) })
        assertTrue(invocation.lineSequence().any { it == work.resolve("reports/program_model.json").toAbsolutePath().toString() })
        assertTrue(invocation.lineSequence().last { it.isNotEmpty() }.endsWith(".candidate"))
        val exporter = work.resolve("scripts/ExportProgramModelOwned.java").readText()
        assertTrue(exporter.contains("program-model export complete"))
        assertTrue(exporter.contains("writeIfAbsentAtomic"))
        assertTrue(exporter.contains("return isAcceptedRecord(record)"))
        assertTrue(exporter.contains("copyBoundFragment"))
        assertTrue(exporter.contains("DECOMPILE_TIMEOUT_SECONDS = 60"))
        assertTrue(exporter.contains("DECOMPILE_RETRY_TIMEOUT_SECONDS = 180"))
        assertTrue(exporter.contains("MAXIMUM_DECOMPILE_INSTRUCTIONS = 500_000"))
        assertTrue(exporter.contains("decompileOptions.setMaxInstructions(MAXIMUM_DECOMPILE_INSTRUCTIONS)"))
        assertTrue(exporter.contains("isRetryableDecompileTimeout(exported)"))
        assertTrue(exporter.contains("exported.failure.contains(\"process: timeout\")"))
        assertTrue(exporter.contains("full-recovery-workers-v1:[1-4]"))
        assertTrue(exporter.contains("ExporterParallelCoordinatorOwnedV1<FunctionMetadata, FunctionExport>"))
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
        assertTrue(exporter.contains("ExporterSemanticFingerprintOwnedV1"))
        assertTrue(exporter.contains("MAXIMUM_CANONICAL_BYTES = 1024L * 1024 * 1024"))
        assertTrue(exporter.contains("semanticStateBinding"))
        assertTrue(exporter.contains("batchCommitmentSha256"))
        assertTrue(exporter.contains("planning-exporter-visible-program"))
        assertTrue(exporter.contains("legacy export state schema 1 has no whole-program semantic binding"))
        assertTrue(exporter.contains("exportFunction(function, null, null, null, evidence, false, DECOMPILE_TIMEOUT_SECONDS)"))
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
        val generatedCommitment = exporter.lastIndexOf("ExporterSemanticFingerprintOwnedV1.commitBatch(\n                        start")
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
        val stateAcceptance = exporter.lastIndexOf("ExporterSemanticFingerprintOwnedV1.requireReusableState(existing, state)")
        val batchReuse = exporter.lastIndexOf("discardPlanningPendingFiles(planningBatchesDirectory, total)")
        assertTrue(semanticPreflight >= 0 && semanticPreflight < stateAcceptance)
        assertTrue(stateAcceptance < batchReuse)
    }

    @Test
    fun `headless adapter terminates an over-budget export with resumable guidance`() = inControlTemporaryDirectory { temp ->
        val home = fakeGhidraHome(temp, complete = false)
        val binary = temp.resolve("input/program").also {
            it.parent.createDirectories()
            it.writeText("binary fixture")
        }
        val work = temp.resolve("analysis")
        val analyzer = GhidraHeadlessProgramModelAnalyzer(
            home,
            GhidraProgramModelExportLimits(Duration.ofSeconds(5), Duration.ofMillis(100)),
        )

        val pidFile = work.resolve("worker.pid")
        try {
            val failure = assertFailsWith<GhidraAnalysisException> { analyzer.analyze(binary, work) }

            assertTrue(failure.message.orEmpty().contains("exceeded 5000 milliseconds"), failure.message)
            assertTrue(failure.message.orEmpty().contains("rerun with the same output directory"), failure.message)
            assertTrue(pidFile.exists(), "owned worker should have started before the timeout: ${failure.message}")
            val pid = pidFile.readText().trim().toLong()
            assertFalse(ProcessHandle.of(pid).map { it.isAlive }.orElse(false), "owned export worker survived timeout")
            assertFalse(work.resolve("reports/program_model.json").exists())
            assertTrue(work.resolve("reports/ghidra_stdout.log").readText().contains("fake export started"))
            assertTrue(work.resolve("reports/ghidra_stderr.log").readText().contains("fake export diagnostic"))
            assertFalse(Thread.currentThread().isInterrupted, "deadline watchdog interrupt leaked to caller")
        } finally {
            if (pidFile.exists()) {
                pidFile.readText().trim().toLongOrNull()?.let { ProcessHandle.of(it).orElse(null) }?.let { process ->
                    if (process.isAlive) {
                        process.destroyForcibly()
                        process.onExit().get(2, TimeUnit.SECONDS)
                    }
                }
            }
        }
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
        val temp = Files.createTempDirectory(Path.of("").toAbsolutePath().normalize().resolve("build"), "program-model-real-")
        val source = temp.resolve("program.c")
        val binary = temp.resolve("program")
        source.writeText(
            "#include <stdio.h>\nstatic int twice(int x) { return x * 2; }\n" +
                "static int *identity(int *pointer) { return pointer; }\n" +
                "static void reset(int *pointer) { *pointer = 0; }\n" +
                "static void *opaque_pointer(void *pointer) { return pointer; }\n" +
                "int main(void) { int value = twice(0); reset(&value); puts(\"resumable-export\"); " +
                "return opaque_pointer(identity(&value)) == &value ? value : 1; }\n",
        )
        val compiler = ProcessBuilder("gcc", "-g", "-O0", source.pathString, "-o", binary.pathString)
            .apply { environment()["TMPDIR"] = temp.resolve("compiler-tmp").createDirectories().pathString }
            .redirectErrorStream(true)
            .start()
        val compilerOutput = compiler.inputStream.bufferedReader().readText()
        check(compiler.waitFor() == 0) { compilerOutput }
        source.deleteExisting()
        val work = temp.resolve("analysis")
        val jvmHome = work.resolve("home").createDirectories()
        val jvmTemp = work.resolve("tmp").createDirectories()
        val analyzer = GhidraHeadlessProgramModelAnalyzer(commandFactory = { invocation ->
            val command = BundledGhidra.locate().analysisCommand(invocation.copy(
                // Ghidra rejects the hidden .t3 component in the repository's absolute checkout path.
                project = Path.of("/proc/self/cwd/ghidra_project"),
            ))
            listOf(command.first(), "-Duser.home=$jvmHome", "-Djava.io.tmpdir=$jvmTemp",
                "-Djna.tmpdir=$jvmTemp", "-XX:-UsePerfData", "-XX:ActiveProcessorCount=4") + command.drop(1)
        })

        val first = analyzer.analyze(binary, work)
        assertEquals(4, first.schemaVersion)
        assertTrue(first.globals.all { it.byteEvidence?.schemaVersion == 2 })
        val firstByName = first.functions.associateBy { it.name }
        assertEquals("int twice(int x)", firstByName.getValue("twice").prototype)
        assertEquals(RecoveryStatus.RECOVERED, firstByName.getValue("twice").status)
        assertEquals("int* identity(int* pointer)", firstByName.getValue("identity").prototype)
        assertEquals(RecoveryStatus.RECOVERED, firstByName.getValue("identity").status)
        assertEquals("void reset(int* pointer)", firstByName.getValue("reset").prototype)
        assertEquals(RecoveryStatus.RECOVERED, firstByName.getValue("reset").status)
        assertEquals("void* opaque_pointer(void* pointer)", firstByName.getValue("opaque_pointer").prototype)
        assertEquals(RecoveryStatus.RECOVERED, firstByName.getValue("opaque_pointer").status)
        assertEquals("int main(void)", firstByName.getValue("main").prototype)
        val modelPath = work.resolve("reports/program_model.json")
        val firstModel = modelPath.readBytes()
        assertTrue(firstModel.toString(Charsets.UTF_8).contains("\"recoveryAssessment\": \"unassessed\""))
        assertEquals(first, decompengine.oracle.structural.CanonicalProgramModelStreaming.readCanonical(firstModel).model)
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
        java.nio.file.Files.write(binary, byteArrayOf(0), java.nio.file.StandardOpenOption.APPEND)
        assertFailsWith<IllegalArgumentException> { analyzer.analyze(binary, work) }
        assertTrue(firstModel.contentEquals(modelPath.readBytes()))
        assertTrue(work.resolve("reports/ghidra_stderr.log").readText().contains("existing output is not a successful result"))
    }

    @Test
    fun `opt in real Ghidra reuses authenticated planning batches deterministically`() {
        if (System.getenv("RUN_REAL_GHIDRA") != "true") return
        val temp = Files.createTempDirectory(Path.of("").toAbsolutePath().normalize().resolve("build"), "program-model-planning-real-")
        val source = temp.resolve("program.c")
        val binary = temp.resolve("program")
        source.writeText(
            "static int twice(int x) { return x * 2; }\n" +
                "int main(void) { return twice(21); }\n",
        )
        val compiler = ProcessBuilder("gcc", "-g", "-O0", source.pathString, "-o", binary.pathString)
            .apply { environment()["TMPDIR"] = temp.resolve("compiler-tmp").createDirectories().pathString }
            .redirectErrorStream(true)
            .start()
        val compilerOutput = compiler.inputStream.bufferedReader().readText()
        check(compiler.waitFor() == 0) { compilerOutput }
        source.deleteExisting()
        val work = temp.resolve("analysis")
        val jvmHome = work.resolve("home").createDirectories()
        val jvmTemp = work.resolve("tmp").createDirectories()
        val analyzer = GhidraHeadlessProgramModelAnalyzer(commandFactory = { invocation ->
            val command = BundledGhidra.locate().analysisCommand(invocation.copy(
                project = Path.of("/proc/self/cwd/ghidra_project"),
            ))
            listOf(command.first(), "-Duser.home=$jvmHome", "-Djava.io.tmpdir=$jvmTemp",
                "-Djna.tmpdir=$jvmTemp", "-XX:-UsePerfData", "-XX:ActiveProcessorCount=4") + command.drop(1)
        },
            recoveryMode = GhidraProgramModelRecoveryMode.PLANNING,
        )

        val first = analyzer.analyze(binary, work)
        assertEquals(4, first.schemaVersion)
        assertTrue(first.globals.all { it.byteEvidence?.schemaVersion == 2 })
        val modelPath = work.resolve("reports/program_model.json")
        val firstModel = modelPath.readBytes()
        assertEquals(first, decompengine.oracle.structural.CanonicalProgramModelStreaming.readCanonical(firstModel).model)
        val batches = modelPath.resolveSibling("program_model.json.export/planning-batches")
        val checkpoints = batches.listDirectoryEntries("*.checkpoint")
        assertTrue(checkpoints.isNotEmpty())

        val resumed = analyzer.analyze(binary, work)

        assertEquals(first, resumed)
        assertTrue(firstModel.contentEquals(modelPath.readBytes()))
        val progress = modelPath.resolveSibling("program_model.json.progress.json").readText()
        assertTrue(progress.contains("\"phase\":\"complete\""))
        assertTrue(progress.contains("\"reused\":${first.functions.size}"), progress)
        val statePath = modelPath.resolveSibling("program_model.json.export/state.json")
        val priorState = statePath.readText()
        assertTrue("\"exporterVersion\":19" in priorState)
        for (historicalVersion in listOf(18, 17, 16, 13, 12, 11)) {
            val historicalState = priorState.replace("\"exporterVersion\":19", "\"exporterVersion\":$historicalVersion")
            statePath.writeText(historicalState)
            assertFailsWith<IllegalArgumentException> { analyzer.analyze(binary, work) }
            assertEquals(historicalState, statePath.readText())
            assertTrue(firstModel.contentEquals(modelPath.readBytes()))
        }
    }

    @Test
    fun `opt in C only native export preserves C bytes and every model fact`() {
        if (System.getenv("RUN_REAL_GHIDRA") != "true") return
        inControlTemporaryDirectory { temp ->
            val source = temp.resolve("fixture.c")
            val binary = temp.resolve("fixture")
            source.writeText(buildString {
                append("""
                    typedef unsigned long fixture_word;
                    typedef struct FixtureRecord { fixture_word value; int kind; char label[16]; } FixtureRecord;
                    FixtureRecord fixture_global = { 17, 3, "fixture-label" };
                    fixture_word fixture_bias = 31;
                    __attribute__((noinline)) fixture_word fixture_switch(FixtureRecord *record, int selector) {
                        switch (selector) {
                """.trimIndent())
                for (index in 0..11) {
                    append("\ncase $index: record->value += ${index * index + 3}; record->kind ^= ${index + 7}; break;")
                }
                append("\ndefault: record->value ^= fixture_bias; record->kind = -1; break;\n}\n")
                append("return record->value + record->kind + record->label[selector & 7];\n}\n")
                append("__attribute__((noinline)) fixture_word fixture_large(fixture_word value) {\n")
                for (index in 1..160) {
                    append("value = (value ^ (value >> ${(index % 7) + 1})) + ${index * 19}UL;\n")
                    if (index % 8 == 0) append("if (value & ${index}UL) value += fixture_bias; else value ^= fixture_global.value;\n")
                }
                append("return value;\n}\n")
                append("__attribute__((noinline)) int aggregate_parameter_probe(FixtureRecord *record) { return record->kind; }\n")
                append("__attribute__((noinline)) int aggregate_value_parameter_probe(FixtureRecord record) { return record.kind; }\n")
                append("__attribute__((noinline)) FixtureRecord aggregate_return_probe(int value) { FixtureRecord record = {value, value + 1, \"return\"}; return record; }\n")
                append("__attribute__((noinline)) int custom_storage_probe(int value) { return value + 5; }\n")
                append("int main(int argc, char **argv) { return (int)(fixture_large(fixture_switch(&fixture_global, argc)) + argv[0][0]); }\n")
            })
            val compilerLog = temp.resolve("compiler.log")
            val compiler = ProcessBuilder(
                "gcc", "-g", "-gdwarf-4", "-O0", "-fno-inline", "-fno-pie", "-no-pie",
                "-fjump-tables", "--param=case-values-threshold=1",
                source.pathString, "-o", binary.pathString,
            ).apply {
                environment()["TMPDIR"] = temp.resolve("compiler-tmp").createDirectories().pathString
            }.redirectErrorStream(true).redirectOutput(compilerLog.toFile()).start()
            try {
                assertTrue(compiler.waitFor(15, TimeUnit.SECONDS), "native fixture compiler timed out")
                assertEquals(0, compiler.exitValue(), compilerLog.readText())
            } finally {
                if (compiler.isAlive) {
                    val children = compiler.toHandle().descendants().use { it.toList() }
                    children.forEach { it.destroyForcibly() }
                    compiler.destroyForcibly()
                    assertTrue(compiler.waitFor(5, TimeUnit.SECONDS), "fixture compiler survived cleanup")
                    children.forEach { it.onExit().get(5, TimeUnit.SECONDS) }
                }
            }
            val candidate = checkNotNull(javaClass.getResourceAsStream("/ghidra_scripts/ExportProgramModelOwned.java"))
                .use { it.readBytes().toString(Charsets.UTF_8) }
            assertEquals(1, Regex(Regex.escape("decompiler.toggleSyntaxTree(true)")).findAll(candidate).count())
            assertEquals(1, Regex(Regex.escape("decompiler.toggleCCode(true)")).findAll(candidate).count())
            // Compare against the actual pre-change exporter, not a candidate-derived listing-only
            // variant that would still exercise the new typed-prototype refusal path.
            val baselineProcess = ProcessBuilder("git", "show",
                "519b16afa06ab64d2b72ad92c46c1baffc24f294:src/main/resources/ghidra_scripts/ExportProgramModelOwned.java")
                .redirectErrorStream(true).start()
            val baseline = baselineProcess.inputStream.bufferedReader().readText()
            check(baselineProcess.waitFor() == 0) { "Could not load the pinned pre-typed exporter: $baseline" }
            assertTrue("decompiler.toggleSyntaxTree(false);" in baseline, "pre-change baseline must disable typed HighFunction output")
            val version = Regex("EXPORTER_VERSION = ([0-9]+);")
            assertEquals("19", checkNotNull(version.find(candidate)).groupValues[1])
            assertEquals("18", checkNotNull(version.find(baseline)).groupValues[1], "baseline is the pinned pre-change exporter")
            val entry = "    protected void run() throws Exception {\n"
            val fixtureSetup = """
                        for (Function fixtureFunction : currentProgram.getFunctionManager().getFunctions(true)) {
                            if (fixtureFunction.getName().equals("fixture_switch")) {
                                if (!setPlateComment(fixtureFunction.getEntryPoint(), "C-only fixture plate comment")) {
                                    throw new IllegalStateException("Could not seed native fixture plate comment");
                                }
                                for (Instruction instruction : currentProgram.getListing().getInstructions(fixtureFunction.getBody(), true)) {
                                    if (!setPreComment(instruction.getAddress(), "C-only fixture instruction comment")) {
                                        throw new IllegalStateException("Could not seed native fixture instruction comment");
                                    }
                                }
                            }
                            if (fixtureFunction.getName().equals("custom_storage_probe")) {
                                ghidra.program.model.listing.Parameter customParameter =
                                    new ghidra.program.model.listing.ParameterImpl("value",
                                        ghidra.program.model.data.IntegerDataType.dataType,
                                        currentProgram.getRegister("esi"), currentProgram,
                                        ghidra.program.model.symbol.SourceType.USER_DEFINED);
                                fixtureFunction.updateFunction(ghidra.program.model.listing.Function.DEFAULT_CALLING_CONVENTION_STRING,
                                    new ghidra.program.model.listing.ReturnParameterImpl(
                                        ghidra.program.model.data.IntegerDataType.dataType, currentProgram),
                                    java.util.List.of(customParameter),
                                    ghidra.program.model.listing.Function.FunctionUpdateType.CUSTOM_STORAGE,
                                    true, ghidra.program.model.symbol.SourceType.USER_DEFINED);
                                if (!fixtureFunction.hasCustomVariableStorage()) {
                                    throw new IllegalStateException("Could not seed custom variable storage");
                                }
                            }
                        }
            """.trimIndent().prependIndent("        ") + "\n"
            println("Native fixture setup (identical in both staged exporters):\n$fixtureSetup")
            println("Native fixture binary SHA256=${sha256(binary.readBytes())}")
            fun seedKnownMetadataFailure(exporter: String): String {
                val methodStart = exporter.indexOf("private FunctionMetadata collectFunctionMetadata(")
                assertTrue(methodStart >= 0, "metadata collector anchor must exist")
                val anchor = "        String failure = null;"
                val failureOffset = exporter.indexOf(anchor, methodStart)
                assertTrue(failureOffset >= 0, "metadata failure accumulator anchor must exist")
                val seeded = anchor + "\n        if (\"custom_storage_probe\".equals(function.getName())) {\n" +
                    "            failure = appendFailure(failure, \"fixture-seeded metadata failure\");\n        }"
                return exporter.replaceRange(failureOffset, failureOffset + anchor.length, seeded)
            }
            fun export(label: String, exporter: String): Pair<RecoveredProgramModel, Path> {
                assertEquals(1, Regex(Regex.escape(entry)).findAll(exporter).count())
                val staged = seedKnownMetadataFailure(exporter).replace(entry, entry + fixtureSetup)
                val stagedHash = sha256(staged.toByteArray())
                val work = temp.resolve(label)
                val jvmHome = work.resolve("home").createDirectories()
                val jvmTemp = work.resolve("tmp").createDirectories()
                val analyzer = GhidraHeadlessProgramModelAnalyzer(
                    commandFactory = { invocation ->
                        invocation.scripts.resolve("ExportProgramModelOwned.java").writeText(staged)
                        val exporterScript = invocation.postScripts.single()
                        val command = BundledGhidra.locate().analysisCommand(invocation.copy(
                            // Ghidra rejects hidden project path components such as a .claude worktree.
                            // The worker cwd is exactly work, so this aliases its existing project directory.
                            project = Path.of("/proc/self/cwd/ghidra_project"),
                            postScripts = listOf(exporterScript.copy(arguments =
                                listOf(stagedHash) + exporterScript.arguments.drop(1))),
                        ))
                        listOf(command.first(), "-Duser.home=$jvmHome", "-Djava.io.tmpdir=$jvmTemp",
                            "-XX:-UsePerfData", "-XX:ActiveProcessorCount=4") + command.drop(1)
                    },
                    limits = GhidraProgramModelExportLimits(wallClockTimeout = Duration.ofSeconds(150)),
                    analysisToolSha256 = BundledGhidra.ARCHIVE_SHA256,
                )
                val start = System.nanoTime()
                val model = try {
                    analyzer.analyze(binary, work)
                } catch (failure: Throwable) {
                    listOf("ghidra_stdout.log", "ghidra_stderr.log").forEach { name ->
                        work.resolve("reports/$name").takeIf { it.exists() }?.let { println(it.readText().takeLast(16_384)) }
                    }
                    throw failure
                }
                println("Native $label source SHA256=${sha256(exporter.toByteArray())} staged SHA256=$stagedHash " +
                    "wallSeconds=${(System.nanoTime() - start) / 1_000_000_000.0} functions=${model.functions.size} " +
                    "globals=${model.globals.size} types=${model.types.size} statuses=${model.functions.groupingBy { it.status }.eachCount()}")
                return model to work.resolve("reports/program_model.json")
            }
            val (before, beforePath) = export("baseline", baseline)
            val (after, afterPath) = export("candidate", candidate)
            assertEquals(before.functions.map { it.decompiledC }, after.functions.map { it.decompiledC }, "typed extraction must not change decompiled C")
            assertEquals(before.functions.map { it.copy(prototype = "", status = RecoveryStatus.RECOVERED) },
                after.functions.map { it.copy(prototype = "", status = RecoveryStatus.RECOVERED) },
                "only prototype and extraction status may change")
            assertEquals(before.globals, after.globals, "global facts remain unchanged")
            assertEquals(before.types, after.types, "type facts remain unchanged")
            assertEquals(after, decompengine.oracle.structural.CanonicalProgramModelStreaming.readCanonical(afterPath.readBytes()).model,
                "typed declarations survive canonical model decoding")
            fun sidecars(modelPath: Path): Map<String, ByteArray> {
                val root = modelPath.resolveSibling("program_model.json.export")
                return Files.walk(root).use { files ->
                    files.filter { Files.isRegularFile(it) && it.fileName.toString() != "state.json" }
                        .toList().associate { root.relativize(it).toString() to it.readBytes() }
                }
            }
            val beforeSidecars = sidecars(beforePath)
            val afterSidecars = sidecars(afterPath)
            val nonFunctionSidecars = beforeSidecars.keys.filter { !it.startsWith("functions/") && !it.startsWith("failures/") }.toSet()
            assertEquals(nonFunctionSidecars, afterSidecars.keys.filter {
                !it.startsWith("functions/") && !it.startsWith("failures/")
            }.toSet(), "global/type evidence record paths")
            beforeSidecars.filterKeys { it in nonFunctionSidecars }.forEach { (name, bytes) ->
                assertTrue(bytes.contentEquals(afterSidecars.getValue(name)), name)
            }
            val beforeState = beforePath.resolveSibling("program_model.json.export/state.json").readText()
            val afterState = afterPath.resolveSibling("program_model.json.export/state.json").readText()
            val sourceIdentity = Regex("\"exporterSha256\":\"[0-9a-f]{64}\"")
            fun comparableState(state: String) = state.replace(sourceIdentity, "\"exporterSha256\":\"SOURCE\"")
                .replace("\"exporterVersion\":18", "\"exporterVersion\":VERSION")
                .replace("\"exporterVersion\":19", "\"exporterVersion\":VERSION")
            assertEquals(comparableState(beforeState), comparableState(afterState), "all other checkpoint state facts")
            val progressKeys = listOf("phase", "completed", "total", "reused")
            val beforeProgress = beforePath.resolveSibling("program_model.json.progress.json").readText()
            val afterProgress = afterPath.resolveSibling("program_model.json.progress.json").readText()
            progressKeys.forEach { key ->
                val field = Regex("\\\"$key\\\":(?:\\\"([^\\\"]*)\\\"|([0-9]+))")
                assertEquals(field.find(beforeProgress)?.value, field.find(afterProgress)?.value, "progress field $key")
            }
            val named = after.functions.associateBy { it.name }
            for (name in listOf("fixture_switch", "fixture_large", "aggregate_parameter_probe", "aggregate_value_parameter_probe",
                "aggregate_return_probe", "custom_storage_probe", "main")) {
                assertTrue(!named.getValue(name).decompiledC.isNullOrBlank(), name)
            }
            assertEquals(RecoveryStatus.PARTIAL, named.getValue("fixture_switch").status,
                "unsupported aggregate parameter must remain partial rather than claim typed recovery")
            assertEquals(RecoveryStatus.PARTIAL, named.getValue("fixture_large").status,
                "unsupported typedef result must remain partial rather than claim typed recovery")
            assertEquals(RecoveryStatus.PARTIAL, named.getValue("custom_storage_probe").status,
                "custom storage under the default convention must not be claimed as an ordinary C ABI")
            assertEquals(RecoveryStatus.PARTIAL, named.getValue("aggregate_parameter_probe").status,
                "a scalar return must not mask the independent aggregate-parameter refusal")
            assertEquals(RecoveryStatus.PARTIAL, named.getValue("aggregate_value_parameter_probe").status,
                "by-value aggregate parameters cannot be flattened into ordinary scalar or pointer ABI")
            assertEquals(RecoveryStatus.PARTIAL, named.getValue("aggregate_return_probe").status,
                "aggregate return storage cannot be represented by the bounded prototype renderer")
            assertEquals(RecoveryStatus.RECOVERED, named.getValue("main").status)
            assertEquals("int main(int argc, char** argv)", named.getValue("main").prototype)
            val switchC = checkNotNull(named.getValue("fixture_switch").decompiledC)
            assertTrue("switch" in switchC && "case " in switchC, switchC)
            assertTrue("C-only fixture plate comment" in switchC, switchC)
            assertTrue("C-only fixture instruction comment" in switchC, switchC)
            assertTrue(checkNotNull(named.getValue("fixture_large").decompiledC).length > 5_000)
            val failureSidecars = afterSidecars.filterKeys { it.startsWith("failures/") }
            assertTrue(failureSidecars.isNotEmpty(), "failure sidecars must be retained")
            fun failureFacts(sidecars: Map<String, ByteArray>): Map<String, String> = sidecars
                .filterKeys { it.startsWith("failures/") }
                .values.mapNotNull { bytes ->
                    val record = kotlinx.serialization.json.Json.parseToJsonElement(bytes.toString(Charsets.UTF_8)).jsonObject
                    val id = record["functionId"]?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.content }
                    val message = record["message"]?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.content }
                    if (id == null || message == null) null else id to message
                }.toMap()
            val previousFailures = failureFacts(beforeSidecars)
            val retainedFailures = failureFacts(afterSidecars)
            assertTrue(previousFailures.isNotEmpty(), "pinned pre-change exporter must include metadata/native failure evidence")
            previousFailures.forEach { (id, message) ->
                assertTrue(id == named.getValue("custom_storage_probe").id && message == "fixture-seeded metadata failure",
                    "the prior diagnostic is an independently seeded metadata failure")
                assertTrue(retainedFailures[id]?.contains(message) == true,
                    "pre-existing failure ID $id and diagnostic must survive typed refusal")
            }
            val customStorageId = named.getValue("custom_storage_probe").id
            assertTrue(failureSidecars.values.any {
                val failure = it.toString(Charsets.UTF_8)
                "\"functionId\":\"$customStorageId\"" in failure && "custom variable storage is unsupported" in failure
            }, "the custom-storage refusal must be retained with the available C extraction")
            val aggregateParameterId = named.getValue("aggregate_parameter_probe").id
            assertTrue(failureSidecars.values.any {
                val failure = it.toString(Charsets.UTF_8)
                "\"functionId\":\"$aggregateParameterId\"" in failure && "unsupported parameter type" in failure
            }, "the scalar-return aggregate-parameter refusal must be retained independently")
            val aggregateReturnId = named.getValue("aggregate_return_probe").id
            assertTrue(failureSidecars.values.any {
                val failure = it.toString(Charsets.UTF_8)
                "\"functionId\":\"$aggregateReturnId\"" in failure && "return" in failure
            }, "aggregate return storage or type refusal must be retained")
            assertTrue(after.globals.any { it.name == "fixture_global" }, after.globals.toString())
            assertTrue(after.globals.any { it.name == "fixture_bias" }, after.globals.toString())
            assertTrue(after.types.any { "struct" in it.declaration && "FixtureRecord" in it.declaration }, after.types.toString())
            assertTrue(after.types.any { "typedef" in it.declaration && "fixture_word" in it.declaration }, after.types.toString())
            println("Native equality PASS model SHA256=${sha256(afterPath.readBytes())} records=${afterSidecars.size} " +
                "failureRecords=${afterSidecars.keys.count { it.startsWith("failures/") }} " +
                "CBytes=${after.functions.sumOf { it.decompiledC?.toByteArray()?.size ?: 0 }} " +
                "largeCBytes=${named.getValue("fixture_large").decompiledC!!.toByteArray().size}")
        }
    }

    @Test
    fun `opt in pure rendering preserves all native exporter bytes against committed baseline`() {
        if (System.getenv("RUN_REAL_GHIDRA") != "true" || System.getenv("RUN_REAL_GHIDRA_PURE_RENDERING") != "true") return
        val repository = Path.of("").toAbsolutePath().normalize().toRealPath()
        val candidate = checkNotNull(javaClass.getResourceAsStream("/ghidra_scripts/ExportProgramModelOwned.java"))
            .use { it.readBytes().toString(Charsets.UTF_8) }
        assertTrue("EXPORTER_VERSION = 19;" in candidate)
        // The baseline is the candidate with only the three pure-rendering call sites restored to their original
        // Formatter/regex implementations, so it keeps every other exporter behavior (byte evidence, workers, phases).
        val renderingEdits = listOf(
            "return ExporterPureRenderingOwnedV1.addressId(\"fn_\", function.getEntryPoint().getOffset());" to
                "return String.format(\"fn_%016x\", function.getEntryPoint().getOffset());",
            "return ExporterPureRenderingOwnedV1.addressId(\"global_\", address.getOffset());" to
                "return String.format(\"global_%016x\", address.getOffset());",
            "        return ExporterPureRenderingOwnedV1.hexDigest(digest);" to
                "        StringBuilder result = new StringBuilder();\n" +
                "        for (byte value : digest) result.append(String.format(\"%02x\", value & 0xff));\n" +
                "        return result.toString();",
            "String cName = ExporterPureRenderingOwnedV1.typeName(type.getName());" to
                "String cName = type.getName().replaceAll(\"[^A-Za-z0-9_]\", \"_\");",
        )
        val baseline = renderingEdits.fold(candidate) { source, (from, to) ->
            assertEquals(1, Regex(Regex.escape(from)).findAll(source).count(), "candidate must contain exactly one $from")
            source.replace(from, to)
        }
        assertTrue(baseline != candidate && "String.format(\"fn_%016x\"" in baseline)
        for (exporter in listOf(baseline, candidate)) {
            assertEquals(1, Regex(Regex.escape("decompiler.toggleSyntaxTree(true)")).findAll(exporter).count())
            assertEquals(1, Regex(Regex.escape("decompiler.toggleCCode(true)")).findAll(exporter).count())
            for (setting in listOf("DECOMPILE_TIMEOUT_SECONDS = 60", "DECOMPILE_RETRY_TIMEOUT_SECONDS = 180",
                "MAXIMUM_DECOMPILE_INSTRUCTIONS = 500_000", "decompileOptions.setMaxInstructions(MAXIMUM_DECOMPILE_INSTRUCTIONS)")) {
                assertTrue(setting in exporter, "both variants must retain $setting")
            }
        }
        val temp = Files.createTempDirectory(repository.resolve("build/exporter-rendering-v16/native").createDirectories(), "equality-")
        val source = temp.resolve("rendering.c")
        val binary = temp.resolve("rendering")
        source.writeText("""
            typedef unsigned long rendering_word;
            typedef enum RenderingKind { KIND_ZERO, KIND_FIRST, KIND_SECOND } RenderingKind;
            typedef struct RenderingRecord { rendering_word value; RenderingKind kind; char label[16]; } RenderingRecord;
            RenderingRecord rendering_global = { 17, KIND_FIRST, "rendering-label" };
            rendering_word rendering_bias = 31;
            RenderingKind rendering_kind = KIND_SECOND;
            __attribute__((noinline)) rendering_word rendering_leaf(RenderingRecord *record, int selector) {
                record->value += rendering_bias;
                record->kind = selector & 1 ? KIND_FIRST : rendering_kind;
                return record->value + record->kind + record->label[selector & 7];
            }
            __attribute__((noinline)) rendering_word rendering_caller(int selector) {
                return rendering_leaf(&rendering_global, selector) + rendering_leaf(&rendering_global, selector + 1);
            }
            int main(int argc, char **argv) { return (int)(rendering_caller(argc) + argv[0][0]); }
        """.trimIndent() + "\n")
        val compilerLog = temp.resolve("compiler.log")
        val compiler = ProcessBuilder("gcc", "-g", "-gdwarf-4", "-O0", "-fno-inline", "-fno-pie", "-no-pie",
            source.pathString, "-o", binary.pathString).apply {
            environment()["TMPDIR"] = temp.resolve("compiler-tmp").createDirectories().pathString
        }.redirectErrorStream(true).redirectOutput(compilerLog.toFile()).start()
        try {
            assertTrue(compiler.waitFor(15, TimeUnit.SECONDS), "native rendering fixture compiler timed out")
            assertEquals(0, compiler.exitValue(), compilerLog.readText())
        } finally {
            if (compiler.isAlive) {
                val children = compiler.toHandle().descendants().use { it.toList() }
                children.forEach { it.destroyForcibly() }
                compiler.destroyForcibly()
                assertTrue(compiler.waitFor(5, TimeUnit.SECONDS), "rendering fixture compiler survived cleanup")
                children.forEach { it.onExit().get(5, TimeUnit.SECONDS) }
            }
        }
        println("Native pure rendering input SHA256=${sha256(binary.readBytes())} retained evidence=$temp")
        fun export(label: String, exporter: String): Pair<RecoveredProgramModel, Path> {
            val work = temp.resolve(label)
            val jvmHome = work.resolve("home").createDirectories()
            val jvmTemp = work.resolve("tmp").createDirectories()
            val exporterHash = sha256(exporter.toByteArray())
            val analyzer = GhidraHeadlessProgramModelAnalyzer(
                commandFactory = { invocation ->
                    invocation.scripts.resolve("ExportProgramModelOwned.java").writeText(exporter)
                    val script = invocation.postScripts.single()
                    // Keep the legacy policy token while explicitly selecting the owned candidate protocol.
                    val arguments = listOf(exporterHash) + script.arguments.drop(1).take(3) +
                        "full-recovery-workers-v1:4" + "owned-model-candidate-v1" + script.arguments.last()
                    val command = BundledGhidra.locate().analysisCommand(invocation.copy(
                        project = Path.of("/proc/self/cwd/ghidra_project"),
                        postScripts = listOf(script.copy(arguments = arguments)),
                    ))
                    listOf("/usr/bin/env", "-u", "JAVA_TOOL_OPTIONS", "-u", "JDK_JAVA_OPTIONS", "-u", "_JAVA_OPTIONS",
                        "TMPDIR=$jvmTemp", "XDG_CONFIG_HOME=$jvmHome/config", "XDG_CACHE_HOME=$jvmHome/cache", "XDG_DATA_HOME=$jvmHome/data",
                        command.first(), "-Duser.home=$jvmHome", "-Djava.io.tmpdir=$jvmTemp", "-Djna.tmpdir=$jvmTemp",
                        "-XX:-UsePerfData", "-XX:ActiveProcessorCount=4") + command.drop(1)
                },
                limits = GhidraProgramModelExportLimits(wallClockTimeout = Duration.ofSeconds(90)),
                analysisToolSha256 = BundledGhidra.ARCHIVE_SHA256,
            )
            val start = System.nanoTime()
            val model = try {
                analyzer.analyze(binary, work)
            } catch (failure: Throwable) {
                listOf("ghidra_stdout.log", "ghidra_stderr.log").forEach { name ->
                    work.resolve("reports/$name").takeIf { it.exists() }?.let { println(it.readText().takeLast(16_384)) }
                }
                throw failure
            }
            println("Native rendering $label source SHA256=$exporterHash wallSeconds=${(System.nanoTime() - start) / 1_000_000_000.0} " +
                "functions=${model.functions.size} globals=${model.globals.size} types=${model.types.size} " +
                "statuses=${model.functions.groupingBy { it.status }.eachCount()}")
            return model to work.resolve("reports/program_model.json")
        }
        val (before, beforePath) = export("baseline-unoptimized", baseline)
        val (after, afterPath) = export("candidate-pure", candidate)
        assertEquals(before, after, "all parsed native function/global/type facts")
        assertTrue(beforePath.readBytes().contentEquals(afterPath.readBytes()), "complete canonical native model bytes")
        fun sidecars(modelPath: Path): Map<String, ByteArray> {
            val root = modelPath.resolveSibling("program_model.json.export")
            return Files.walk(root).use { files ->
                files.filter { Files.isRegularFile(it) && it.fileName.toString() != "state.json" }
                    .toList().associate { root.relativize(it).toString() to it.readBytes() }
            }
        }
        val beforeSidecars = sidecars(beforePath)
        val afterSidecars = sidecars(afterPath)
        assertEquals(beforeSidecars.keys, afterSidecars.keys, "all native function/global/type/failure sidecar paths")
        beforeSidecars.forEach { (name, bytes) -> assertTrue(bytes.contentEquals(afterSidecars.getValue(name)), "native sidecar $name") }
        val beforeState = beforePath.resolveSibling("program_model.json.export/state.json").readText()
        val afterState = afterPath.resolveSibling("program_model.json.export/state.json").readText()
        assertTrue("\"exporterVersion\":19" in beforeState)
        assertTrue("\"exporterVersion\":19" in afterState)
        assertTrue("\"decompilationWorkers\":4" in beforeState && "\"decompilationWorkers\":4" in afterState)
        val sourceIdentity = Regex("\"exporterSha256\":\"[0-9a-f]{64}\"")
        assertEquals(beforeState.replace(sourceIdentity, "\"exporterSha256\":\"SOURCE\""),
            afterState.replace(sourceIdentity, "\"exporterSha256\":\"SOURCE\""),
            "worker-parity state must match at the owned exporter version after source-hash normalization")
        assertTrue(beforePath.resolveSibling("program_model.json.progress.json").readBytes()
            .contentEquals(afterPath.resolveSibling("program_model.json.progress.json").readBytes()), "exact native final progress/status bytes")
        val named = after.functions.associateBy { it.name }
        for (name in listOf("rendering_leaf", "rendering_caller", "main")) {
            assertEquals(RecoveryStatus.RECOVERED, named.getValue(name).status, name)
            assertTrue(!named.getValue(name).decompiledC.isNullOrBlank(), name)
        }
        assertTrue(after.globals.any { it.name == "rendering_global" })
        assertTrue(after.globals.any { it.name == "rendering_bias" })
        assertTrue(after.types.any { "RenderingRecord" in it.declaration && "struct" in it.declaration })
        assertTrue(after.types.any { "RenderingKind" in it.declaration && "typedef int" in it.declaration })
        assertTrue(after.types.any { "rendering_word" in it.declaration && "typedef" in it.declaration })
        println("Native pure rendering equality PASS model SHA256=${sha256(afterPath.readBytes())} sidecars=${afterSidecars.size} " +
            "failureSidecars=${afterSidecars.keys.count { it.startsWith("failures/") }} CBytes=${after.functions.sumOf { it.decompiledC?.toByteArray()?.size ?: 0 }}")
    }

    private fun fakeGhidraHome(temp: Path, complete: Boolean): (GhidraInvocation) -> List<String> {
        val home = temp.resolve(if (complete) "fake-ghidra" else "slow-ghidra")
        val executable = home.resolve("fake-worker")
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
                printf '%s\n' "${'$'}${'$'}" > "${'$'}PWD/worker.pid"
                printf 'fake export started\n'
                printf 'fake export diagnostic\n' >&2
                while :; do :; done
                """.trimIndent() + "\n"
            },
        )
        executable.toFile().setExecutable(true)
        return fakeGhidraCommand(executable)
    }
}
