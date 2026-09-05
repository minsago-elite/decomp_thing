package decompengine.oracle.gcc

import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.analysis.BundledGhidra
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.fulltree.FullTreeDiskScratchEvidence
import decompengine.oracle.fulltree.FullTreeDiskScratchPolicy
import decompengine.oracle.fulltree.boundedLiveOracleUnitJournal
import decompengine.project.ProgramModelJson
import decompengine.project.DeterministicModulePlanner
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.time.Instant
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.opentest4j.TestAbortedException

class GccBundledContainedExecutionTest {
    @Test
    fun `authored ELF completes bundled direct API export in retained scope without benchmark or release authority`() {
        withRequiredProvisioning {
            val bundle = configuredDirectory("DECOMP_TEST_BUNDLED_GHIDRA_ROOT")
            val mount = configuredDirectory("DECOMP_TEST_BUNDLED_GHIDRA_EXT4_SCRATCH")
            assumeLiveTools()
            assertTrue(names(mount).isEmpty(), "dedicated bundled-analysis fixture slot requires trusted reset")
            val fixture = Files.createTempDirectory("gcc-bundled-contained-execution-")
            Files.setPosixFilePermissions(fixture, PosixFilePermissions.fromString("rwx------"))
            try {
                val intent = authoredIntent(fixture, bundle)
                val byRole = intent.artifacts.associateBy { it.role }
                val journal = privateDirectory(fixture.resolve("journal"))
                val since = Instant.now().epochSecond
                var owner: GccBundledPreparedOperation? = null
                var definition: GccCompilerEngineValidatedContainmentDefinition? = null
                var primaryFailure: Throwable? = null
                try {
                    val prepared = GccBundledOperationCoordinator.prepareNew(intent, journal, mount)
                    owner = prepared
                    definition = GccCompilerEngineContainmentContract.parseDefinitionForLiveController(prepared.definitionBytes)
                    val selectedDefinition = checkNotNull(definition)
                    val output = selectedDefinition.outputLease.path
                    val disk = FullTreeDiskScratchEvidence.parseCanonical(prepared.diskEvidenceBytes)
                    assertEquals("ext4", disk.filesystemType)
                    assertTrue(disk.mountFlags.containsAll(listOf("rw", "nodev", "nosuid", "noexec", "noatime")))
                    assertEquals(mount, output.parent.parent)
                    assertEquals(listOf("reports", "state", "tmp"), names(output))
                    assertFalse(prepared.startAuthorized)
                    assertFalse(prepared.releaseEligible)
                    val executed = prepared.execute()
                    val receiptBytes = executed.executionReceiptBytes
                    val receipt = OracleJson.parseCanonical(receiptBytes).jsonObject
                    assertLinkedRecord(receipt, intent, "gcc-bundled-command-executed-v1")
                    val command = receipt.getValue("execution").jsonObject
                    assertEquals(OracleArtifacts.sha256(OracleJson.canonicalBytes(command)), receipt.getValue("executionSha256").jsonPrimitive.content)
                    assertExecution(command, intent)
                    executed.executionReceiptBytes[0] = '!'.code.toByte()
                    assertContentEquals(receiptBytes, executed.executionReceiptBytes)
                    val assessment = assertExport(output, byRole)
                    assertTrue(assessment.functionCount in 1..512)
                    assertEquals(1L, assessment.planningBatchCount)
                    assertEquals("non-authoritative-byte-assessment", assessment.authority)
                    assertEquals(assessment.programModelSha256, executed.assessment.programModelSha256)
                    assertEquals(assessment.semanticSha256, executed.assessment.semanticSha256)
                    val exportBytes = executed.exportAssessmentReceiptBytes
                    val export = OracleJson.parseCanonical(exportBytes).jsonObject
                    assertLinkedRecord(export, intent, "gcc-bundled-command-export-assessed-v1")
                    assertEquals(OracleArtifacts.sha256(receiptBytes), export.getValue("previousSha256").jsonPrimitive.content)
                    assertEquals(OracleArtifacts.sha256(OracleJson.canonicalBytes(export.getValue("assessment"))), export.getValue("assessmentSha256").jsonPrimitive.content)
                    val exportTime = export.getValue("assessment").jsonObject.getValue("operationWallTime").jsonObject
                    val executionTime = command.getValue("operationWallTime").jsonObject
                    assertEquals(executionTime.getValue("startedMonotonicNanos"), exportTime.getValue("startedMonotonicNanos"))
                    assertTrue(exportTime.getValue("elapsedNanos").jsonPrimitive.long >= executionTime.getValue("elapsedNanos").jsonPrimitive.long)
                    assertTrue(exportTime.getValue("remainingNanos").jsonPrimitive.long > 0)
                    executed.exportAssessmentReceiptBytes[0] = '!'.code.toByte()
                    assertContentEquals(exportBytes, executed.exportAssessmentReceiptBytes)
                    retainFixtureEvidence(fixture, intent, selectedDefinition, receiptBytes, exportBytes, assessment)
                    assertCopiedExportRejectsIdentityAndLinks(fixture, output, intent.artifacts, assessment)
                    assertFailsWith<IllegalStateException> { prepared.execute() }
                    prepared.close()
                    prepared.close()
                    owner = null
                    assertTrue(Files.isDirectory(output, LinkOption.NOFOLLOW_LINKS), "scope absence must not pretend to release the disk lease")
                    assertTrue(Files.isRegularFile(output.parent.resolve("lease.json"), LinkOption.NOFOLLOW_LINKS))
                    assertTrue(Files.isDirectory(journal.resolve(".gcc-bundled-operation-${intent.operationId}"), LinkOption.NOFOLLOW_LINKS))
                    assertEquals(listOf(output.parent.fileName.toString()), names(mount))
                    println("Bundled contained authored-ELF fixture: model=${assessment.programModelSha256}, functions=${assessment.functionCount}, execution=${OracleArtifacts.sha256(receiptBytes)}, residue retained for trusted fixture-filesystem teardown")
                } catch (failure: Throwable) {
                    primaryFailure = failure
                    definition?.let { selected ->
                        val diagnostic = runCatching { boundedLiveOracleUnitJournal(selected.unitName, since) }
                            .getOrElse { "exact-unit journal unavailable: ${it.javaClass.name}" }
                        failure.addSuppressed(AssertionError("Bundled contained export diagnostics:\n$diagnostic"))
                        for (name in listOf("contained-command.stdout", "contained-command.stderr")) {
                            val log = selected.outputLease.path.resolve(checkNotNull(intent.bundledRuntime.freshControlDirectoryName(selected.outputLease.path)))
                                .resolve("reports").resolve(name)
                            if (Files.isRegularFile(log, LinkOption.NOFOLLOW_LINKS)) {
                                val captured = runCatching { boundedRead(log, MAXIMUM_LOG_BYTES).decodeToString() }
                                    .getOrElse { "bounded log unavailable: ${it.javaClass.name}" }
                                failure.addSuppressed(AssertionError("$name:\n${captured.take(16 * 1024)}"))
                            }
                        }
                    }
                    throw failure
                } finally {
                    try {
                        owner?.close()
                    } catch (cleanupFailure: Throwable) {
                        val original = primaryFailure
                        if (original == null) throw cleanupFailure
                        if (original !== cleanupFailure) original.addSuppressed(cleanupFailure)
                    }
                }
            } finally {
                Files.walk(fixture).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
            }
        }
    }

    private fun assertLinkedRecord(record: JsonObject, intent: GccBundledOperationIntent, provider: String) {
        assertEquals(provider, record.getValue("provider").jsonPrimitive.content)
        assertEquals(intent.operationId, record.getValue("operationId").jsonPrimitive.content)
        assertEquals(intent.requestSha256, record.getValue("intentSha256").jsonPrimitive.content)
        assertFalse(record.getValue("complete").jsonPrimitive.boolean)
        assertFalse(record.getValue("releaseEligible").jsonPrimitive.boolean)
        assertEquals(
            OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(record - "recordSha256"))),
            record.getValue("recordSha256").jsonPrimitive.content,
        )
    }

    @Test
    fun `authored multi-batch ELF resumes under the same owner and matches fresh model and plan`() = withRequiredProvisioning {
        val bundle = configuredDirectory("DECOMP_TEST_BUNDLED_GHIDRA_ROOT")
        val resumedMount = configuredDirectory("DECOMP_TEST_BUNDLED_GHIDRA_RESUME_EXT4_SCRATCH")
        val freshMount = configuredDirectory("DECOMP_TEST_BUNDLED_GHIDRA_RESUME_CONTROL_EXT4_SCRATCH")
        assumeLiveTools()
        assertTrue(resumedMount != freshMount && names(resumedMount).isEmpty() && names(freshMount).isEmpty())
        val fixture = Files.createTempDirectory("gcc-bundled-contained-resume-")
        Files.setPosixFilePermissions(fixture, PosixFilePermissions.fromString("rwx------"))
        var succeeded = false
        val outputs = arrayListOf<Path>()
        try {
            val intent = authoredIntent(fixture, bundle, interrupted = true)
            val artifacts = intent.artifacts.associateBy { it.role }
            val journal = privateDirectory(fixture.resolve("journal"))
            var resumedModel: ByteArray
            var resumedPlan: ByteArray
            var resumedEvidence: Path
            var resumedReceiptSha256: String
            GccBundledOperationCoordinator.prepareNew(intent, journal, resumedMount).use { owner ->
                val definition = GccCompilerEngineContainmentContract.parseDefinitionForLiveController(owner.definitionBytes)
                outputs.add(definition.outputLease.path)
                val stopped = owner.executeUntilCheckpoint(512)
                assertTrue(stopped.assessment.completed >= 512 && stopped.assessment.completed <= stopped.assessment.functionCount)
                val stoppedReceipt = OracleJson.parseCanonical(stopped.executionReceiptBytes).jsonObject
                assertLinkedRecord(stoppedReceipt, intent, "gcc-bundled-command-interrupted-v1")
                val stoppedCommand = stoppedReceipt.getValue("execution").jsonObject
                assertEquals("kotlin-lease-contained-command-interrupted-v1", stoppedCommand.getValue("provider").jsonPrimitive.content)
                for (field in listOf("unitAbsent", "cgroupAbsent", "processesAbsent")) assertTrue(stoppedCommand.getValue(field).jsonPrimitive.boolean)
                val originalJournal = journal.resolve(".gcc-bundled-operation-${intent.operationId}")
                val originalRecords = names(originalJournal).associateWith { boundedRead(originalJournal.resolve(it), MAXIMUM_METADATA_BYTES) }
                owner.requireInterruptedStateCurrent()
                val result = owner.resume()
                assertEquals(stopped.assessment.completed, result.assessment.reused)
                assertFalse(result.complete)
                assertFalse(result.releaseEligible)
                val receipt = OracleJson.parseCanonical(result.executionReceiptBytes).jsonObject
                assertLinkedRecord(receipt, intent, "gcc-bundled-resume-executed-v1")
                val exportReceipt = OracleJson.parseCanonical(result.exportAssessmentReceiptBytes).jsonObject
                assertLinkedRecord(exportReceipt, intent, "gcc-bundled-resume-export-assessed-v1")
                assertEquals(OracleArtifacts.sha256(result.executionReceiptBytes), exportReceipt.getValue("previousSha256").jsonPrimitive.content)
                val command = receipt.getValue("execution").jsonObject
                assertNotEquals(stoppedCommand.getValue("controlDirectory"), command.getValue("controlDirectory"))
                assertExecution(command, intent)
                assertEquals(result.assessment.programModelSha256, assertExport(definition.outputLease.path, artifacts).programModelSha256)
                originalRecords.forEach { (name, bytes) -> assertContentEquals(bytes, boundedRead(originalJournal.resolve(name), MAXIMUM_METADATA_BYTES)) }
                assertEquals(17, names(originalJournal).size)
                resumedModel = boundedRead(definition.outputLease.path.resolve("reports/program_model.json"), MAXIMUM_MODEL_BYTES)
                resumedPlan = authoredPlan(resumedModel)
                resumedReceiptSha256 = OracleArtifacts.sha256(result.executionReceiptBytes)
                resumedEvidence = retainFixtureEvidence(fixture, intent, definition, result.executionReceiptBytes, result.exportAssessmentReceiptBytes,
                    result.assessment, journal, resumedPlan)
                assertFails { owner.resume() }
            }
            val freshIntent = GccBundledOperationIntent("4".repeat(64), intent.engineId, GccCompilerEngineContainmentRunKind.FRESH_CONTROL,
                intent.artifacts, intent.bundledRuntime, intent.budgets, intent.diskPolicy)
            val freshJournal = privateDirectory(fixture.resolve("journal-fresh"))
            GccBundledOperationCoordinator.prepareNew(freshIntent, freshJournal, freshMount).use { owner ->
                val definition = GccCompilerEngineContainmentContract.parseDefinitionForLiveController(owner.definitionBytes)
                outputs.add(definition.outputLease.path)
                val result = owner.execute()
                assertEquals(0L, result.assessment.reused)
                val freshModel = boundedRead(definition.outputLease.path.resolve("reports/program_model.json"), MAXIMUM_MODEL_BYTES)
                val freshPlan = authoredPlan(freshModel)
                val destination = retainFixtureEvidence(fixture, freshIntent, definition, result.executionReceiptBytes,
                    result.exportAssessmentReceiptBytes, result.assessment, freshJournal, freshPlan)
                assertContentEquals(resumedModel, freshModel, "resumed model differs from normal fresh import/analysis")
                assertContentEquals(resumedPlan, freshPlan, "planner-derived ownership differs")
                readOnlyFile(destination.resolve("resume-comparison.json"), OracleJson.canonicalBytes(JsonObject(mapOf(
                    "fixtureOnly" to JsonPrimitive(true), "benchmarkAccepted" to JsonPrimitive(false),
                    "releaseEligible" to JsonPrimitive(false),
                    "resumedEvidenceDirectory" to JsonPrimitive(resumedEvidence.fileName.toString()),
                    "freshEvidenceDirectory" to JsonPrimitive(destination.fileName.toString()),
                    "resumedExecutionReceiptSha256" to JsonPrimitive(resumedReceiptSha256),
                    "freshExecutionReceiptSha256" to JsonPrimitive(OracleArtifacts.sha256(result.executionReceiptBytes)),
                    "modelSha256" to JsonPrimitive(OracleArtifacts.sha256(freshModel)),
                    "plannerDerivedPlanSha256" to JsonPrimitive(OracleArtifacts.sha256(freshPlan)),
                    "functions" to JsonPrimitive(result.assessment.functionCount),
                ))))
            }
            succeeded = true
        } catch (failure: Throwable) {
            runCatching { retainResumeFailure(fixture, outputs) }.exceptionOrNull()?.let(failure::addSuppressed)
            throw failure
        } finally {
            if (succeeded) Files.walk(fixture).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
            else println("Failed authored resume fixture retained for diagnosis: $fixture")
        }
    }

    private fun retainResumeFailure(fixture: Path, outputs: List<Path>) {
        val parent = Path.of("build/contained-ghidra-evidence").toAbsolutePath().normalize()
        Files.createDirectories(parent)
        val target = Files.createTempDirectory(parent, "failed-authored-resume-")
        var total = 0L
        fun copy(source: Path, relative: String, bound: Int = MAXIMUM_METADATA_BYTES) {
            if (!Files.isRegularFile(source, LinkOption.NOFOLLOW_LINKS)) return
            assertEquals(source.parent, source.parent.toRealPath(), "diagnostic parent must not be linked")
            val bytes = boundedRead(source, bound)
            total += bytes.size
            assertTrue(total <= 64L * 1024 * 1024)
            val destination = target.resolve(relative)
            Files.createDirectories(destination.parent)
            readOnlyFile(destination, bytes)
        }
        for (name in listOf("compiler.log", "compiler-command.json", "inputs/authored.c")) copy(fixture.resolve(name), name)
        for (rootName in listOf("journal", "journal-fresh")) {
            val root = fixture.resolve(rootName)
            if (!Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)) continue
            for (operation in names(root)) {
                val directory = root.resolve(operation)
                if (!Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) continue
                for (name in names(directory)) copy(directory.resolve(name), "$rootName/$operation/$name", MAXIMUM_MODEL_BYTES)
            }
        }
        outputs.forEachIndexed { index, output ->
            if (Files.isDirectory(output, LinkOption.NOFOLLOW_LINKS)) for (control in names(output).filter { it.matches(Regex("control-[a-f0-9]{64}")) }) {
                for (log in listOf("contained-command.stdout", "contained-command.stderr")) {
                    copy(output.resolve(control).resolve("reports").resolve(log), "output-$index/$control/$log", MAXIMUM_LOG_BYTES)
                }
            }
        }
        println("Retained bounded failed resume diagnostics: $target")
    }

    private fun authoredPlan(model: ByteArray): ByteArray = DeterministicModulePlanner(
        maximumEntities = 100_000, maximumDependencyEdges = 1_000_000, maximumWorkUnits = 10_000_000,
    ).plan(ProgramModelJson.readCanonical(model)).toJson().toByteArray(Charsets.UTF_8)

    private fun assertExecution(command: JsonObject, intent: GccBundledOperationIntent) {
        assertEquals("kotlin-lease-contained-command-execution-v1", command.getValue("provider").jsonPrimitive.content)
        assertEquals(1L, command.getValue("schemaVersion").jsonPrimitive.long)
        assertEquals(0L, command.getValue("childExitCode").jsonPrimitive.long)
        for (field in listOf("unitAbsent", "cgroupAbsent", "processesAbsent")) {
            assertTrue(command.getValue(field).jsonPrimitive.boolean, field)
        }
        assertFalse(command.getValue("releaseEligible").jsonPrimitive.boolean)
        assertEquals(
            OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(command - "executionSha256"))),
            command.getValue("executionSha256").jsonPrimitive.content,
        )
        assertTrue(command.getValue("derivationWallNanos").jsonPrimitive.long in 1..intent.budgets.wallClockMillis * 1_000_000L)
        val wallTime = command.getValue("operationWallTime").jsonObject
        assertEquals(intent.budgets.wallClockMillis, wallTime.getValue("maximumWallMillis").jsonPrimitive.long)
        val elapsed = wallTime.getValue("elapsedNanos").jsonPrimitive.long
        val remaining = wallTime.getValue("remainingNanos").jsonPrimitive.long
        assertTrue(elapsed >= command.getValue("derivationWallNanos").jsonPrimitive.long)
        assertTrue(remaining > 0)
        assertEquals(intent.budgets.wallClockMillis * 1_000_000L, elapsed + remaining)
        val cgroup = command.getValue("cgroup").jsonObject
        assertTrue(cgroup.getValue("peakResidentBytes").jsonPrimitive.long in 1..intent.budgets.maximumResidentBytes)
        assertTrue(cgroup.getValue("cpuNanos").jsonPrimitive.long > 0)
        assertEquals(0L, cgroup.getValue("memoryOomEvents").jsonPrimitive.long)
        assertEquals(0L, cgroup.getValue("memoryOomKillEvents").jsonPrimitive.long)
    }

    private fun assertExport(
        output: Path,
        byRole: Map<GccCompilerEngineContainmentArtifactRole, GccCompilerEngineContainmentArtifactIdentity>,
    ): GccCompletedRunAssessment {
        val reports = output.resolve("reports")
        val modelBytes = boundedRead(reports.resolve("program_model.json"), MAXIMUM_MODEL_BYTES)
        val stateRoot = reports.resolve("program_model.json.export")
        val state = boundedRead(stateRoot.resolve("state.json"), MAXIMUM_METADATA_BYTES)
        val progress = boundedRead(reports.resolve("program_model.json.progress.json"), MAXIMUM_METADATA_BYTES)
        val stateDocument = OracleJson.parse(state).jsonObject
        assertEquals(byRole.getValue(GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY).sha256, stateDocument.getValue("inputSha256").jsonPrimitive.content)
        assertEquals(byRole.getValue(GccCompilerEngineContainmentArtifactRole.EXPORTER_SOURCE).sha256, stateDocument.getValue("exporterSha256").jsonPrimitive.content)
        assertEquals(BundledGhidra.ARCHIVE_SHA256, stateDocument.getValue("analysisToolSha256").jsonPrimitive.content)
        assertEquals("planning", stateDocument.getValue("recoveryMode").jsonPrimitive.content)
        val batchRoot = stateRoot.resolve("planning-batches")
        val batchNames = names(batchRoot)
        val checkpoints = batchNames.filter { it.endsWith(".checkpoint") }
        assertTrue(checkpoints.size in 1..32, "authored fixture checkpoint count is outside its bound")
        val bases = checkpoints.map { it.removeSuffix(".checkpoint") }
        assertEquals(
            bases.flatMap { base -> listOf(".checkpoint", ".functions.fragment", ".globals.fragment", ".types.fragment", ".failures.fragment").map { base + it } }.sorted(),
            batchNames,
        )
        val batches = bases.map { base -> GccPlanningBatchBytes(
            boundedRead(batchRoot.resolve(base + ".checkpoint"), MAXIMUM_METADATA_BYTES),
            boundedRead(batchRoot.resolve(base + ".functions.fragment"), MAXIMUM_MODEL_BYTES),
            boundedRead(batchRoot.resolve(base + ".globals.fragment"), MAXIMUM_MODEL_BYTES),
            boundedRead(batchRoot.resolve(base + ".types.fragment"), MAXIMUM_MODEL_BYTES),
            boundedRead(batchRoot.resolve(base + ".failures.fragment"), MAXIMUM_MODEL_BYTES),
        ) }
        val assessed = GccCompilerEngineResumeByteValidator.assessCompletedRun(state, progress, batches, modelBytes)
        val modelDocument = OracleJson.parse(modelBytes, StrictJsonLimits(maximumInputBytes = MAXIMUM_MODEL_BYTES)).jsonObject
        assertEquals(byRole.getValue(GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY).sha256, modelDocument.getValue("inputSha256").jsonPrimitive.content)
        val model = ProgramModelJson.readCanonical(modelBytes)
        assertTrue(model.functions.any { it.name == "fixture_increment" })
        assertTrue(model.functions.any { it.name == "main" })
        assertEquals(model.functions.size.toLong(), assessed.functionCount)
        assertEquals(OracleArtifacts.sha256(modelBytes), assessed.programModelSha256)
        return assessed
    }

    @Test
    fun `authored resume input contains all required defined functions`() {
        assumeTrue(System.getProperty("os.name") == "Linux" && Files.isExecutable(Path.of("/usr/bin/cc")) && Files.isExecutable(Path.of("/usr/bin/nm")))
        val fixture = Files.createTempDirectory("gcc-authored-resume-input-")
        try {
            val inputs = compileAuthoredFixture(fixture, interrupted = true)
            assertTrue(Files.size(inputs.resolve("authored.elf")) <= 8 * 1024 * 1024)
            val output = fixture.resolve("symbols.log")
            val process = ProcessBuilder("/usr/bin/nm", "--defined-only", "--format=posix", inputs.resolve("authored.elf").toString())
                .redirectErrorStream(true).redirectOutput(output.toFile()).start()
            try {
                assertTrue(process.waitFor(10, TimeUnit.SECONDS))
                assertEquals(0, process.exitValue())
                val symbols = boundedRead(output, MAXIMUM_METADATA_BYTES).decodeToString().lineSequence().map { it.substringBefore(' ') }.toSet()
                assertEquals(4096, symbols.count { it.startsWith("fixture_step_") })
                assertTrue(symbols.containsAll(listOf("main", "fixture_increment", "fixture_state")))
            } finally {
                if (process.isAlive) { process.destroyForcibly(); assertTrue(process.waitFor(5, TimeUnit.SECONDS)) }
            }
        } finally {
            Files.walk(fixture).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }

    private fun compileAuthoredFixture(fixture: Path, interrupted: Boolean): Path {
        val inputs = privateDirectory(fixture.resolve("inputs"))
        val source = inputs.resolve("authored.c")
        val sourceText = if (!interrupted) "int fixture_increment(int value) { return value + 7; }\nint main(void) { return fixture_increment(5); }\n"
            else buildString {
                append("int fixture_increment(int value) { return value + 7; }\n")
                append("volatile unsigned fixture_state[64];\n")
                for (index in 0 until 4096) {
                    append("unsigned fixture_step_$index(unsigned value) { unsigned next = value ^ ${index + 1}u; ")
                    append("fixture_state[${index % 64}] = next; return next + fixture_state[${(index + 1) % 64}]; }\n")
                }
                append("int main(void) { unsigned value = fixture_increment(5);\n")
                for (index in 0 until 4096) append("value = fixture_step_$index(value);\n")
                append("return (int)(value & 255u); }\n")
            }
        assertTrue(sourceText.toByteArray().size <= MAXIMUM_METADATA_BYTES)
        Files.writeString(source, sourceText)
        val binary = inputs.resolve("authored.elf")
        val compilerLog = fixture.resolve("compiler.log")
        val compilerCommand = listOf(
            Path.of("/usr/bin/cc").toRealPath().toString(), "-g", "-O0", "-fno-pie", "-no-pie", "-fno-stack-protector",
            source.toString(), "-o", binary.toString(),
        )
        readOnlyFile(fixture.resolve("compiler-command.json"), OracleJson.canonicalBytes(JsonArray(compilerCommand.map(::JsonPrimitive))))
        val compiler = ProcessBuilder(compilerCommand).redirectErrorStream(true).redirectOutput(compilerLog.toFile()).start()
        try {
            compiler.outputStream.close()
            assertTrue(compiler.waitFor(60, TimeUnit.SECONDS), "authored fixture compilation timed out")
            assertEquals(0, compiler.exitValue(), boundedRead(compilerLog, MAXIMUM_METADATA_BYTES).decodeToString())
        } finally {
            if (compiler.isAlive) {
                compiler.destroyForcibly()
                assertTrue(compiler.waitFor(5, TimeUnit.SECONDS), "authored fixture compiler did not exit")
            }
        }
        Files.setPosixFilePermissions(binary, PosixFilePermissions.fromString("r--------"))
        assertContentEquals(byteArrayOf(0x7f, 0x45, 0x4c, 0x46), Files.newInputStream(binary).use { it.readNBytes(4) })
        return inputs
    }

    private fun authoredIntent(fixture: Path, bundle: Path, interrupted: Boolean = false): GccBundledOperationIntent {
        val inputs = compileAuthoredFixture(fixture, interrupted)
        val source = inputs.resolve("authored.c")
        val binary = inputs.resolve("authored.elf")
        val bundleReference = GccBundledGhidraDeploymentReference.open().use { it.reference }
        val runtime = GccBundledGhidraRuntime(bundle, bundleReference.classPath.map { relative ->
            val entry = bundleReference.entries.getValue(relative)
            GccBundledGhidraClassPathEntry(bundle.resolve(relative), checkNotNull(entry.bytes), checkNotNull(entry.sha256))
        })
        val bootRoot = Path.of(checkNotNull(System.getProperty("decompengine.oracle.gcc.bootKeeperClasspathRoot"))).toRealPath()
        val bootEntries = GccKotlinBootClasspathReference.open().use { it.entries }
        val bootManifest = readOnlyFile(inputs.resolve("boot-classpath.json"), OracleJson.canonicalBytes(JsonObject(mapOf(
            "schemaVersion" to JsonPrimitive(1),
            "provider" to JsonPrimitive("gcc-kotlin-boot-classpath-manifest-v1"),
            "entries" to JsonArray(bootEntries.map { entry -> JsonObject(mapOf(
                "path" to JsonPrimitive(bootRoot.resolve(entry.logicalName).toString()),
                "bytes" to JsonPrimitive(entry.bytes), "sha256" to JsonPrimitive(entry.sha256),
            )) }),
        ))))
        val exporter = checkNotNull(javaClass.getResourceAsStream("/ghidra_scripts/ExportProgramModel.java")).use { it.readNBytes(4 * 1024 * 1024 + 1) }
        assertTrue(exporter.size in 1..4 * 1024 * 1024)
        val tools = mapOf(
            GccCompilerEngineContainmentArtifactRole.JAVA_EXECUTABLE to Path.of(System.getProperty("java.home"), "bin", "java"),
            GccCompilerEngineContainmentArtifactRole.BUBBLEWRAP_EXECUTABLE to Path.of("/usr/bin/bwrap"),
            GccCompilerEngineContainmentArtifactRole.RESOURCE_LIMITER_EXECUTABLE to Path.of("/usr/bin/prlimit"),
            GccCompilerEngineContainmentArtifactRole.SYSTEMD_RUN_EXECUTABLE to Path.of("/usr/bin/systemd-run"),
            GccCompilerEngineContainmentArtifactRole.SYSTEMCTL_EXECUTABLE to Path.of("/usr/bin/systemctl"),
            GccCompilerEngineContainmentArtifactRole.SYSTEMD_BUSCTL_EXECUTABLE to Path.of("/usr/bin/busctl"),
        )
        val artifacts = GCC_BUNDLED_CONTAINMENT_ARTIFACT_ROLES.map { role ->
            val path = when (role) {
                GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY -> binary
                GccCompilerEngineContainmentArtifactRole.BOOT_KEEPER_CLASSPATH -> bootManifest
                GccCompilerEngineContainmentArtifactRole.GHIDRA_BRIDGE_JAR -> bundle.resolve("decomp-ghidra-bridge.jar")
                GccCompilerEngineContainmentArtifactRole.GHIDRA_EXPORT_GUARD -> bundle.resolve("scripts/RunBundledExports.class")
                GccCompilerEngineContainmentArtifactRole.GHIDRA_RUNTIME_MANIFEST -> bundle.resolve("bundle.sha256")
                GccCompilerEngineContainmentArtifactRole.EXPORTER_SOURCE -> readOnlyFile(inputs.resolve("ExportProgramModel.java"), exporter)
                GccCompilerEngineContainmentArtifactRole.GHIDRA_ARCHIVE -> Path.of(checkNotNull(System.getProperty("decompengine.ghidra.provenanceArchive"))).toRealPath()
                else -> tools[role]?.toRealPath() ?: readOnlyFile(inputs.resolve("${role.wireName}.json"), OracleJson.canonicalBytes(JsonObject(mapOf(
                    "fixtureOnly" to JsonPrimitive(true), "role" to JsonPrimitive(role.wireName),
                    "authoredSourceSha256" to JsonPrimitive(sha256(source)),
                ))))
            }
            GccCompilerEngineContainmentArtifactIdentity(role, path, Files.size(path), sha256(path))
        }
        return GccBundledOperationIntent(
            OPERATION_ID, "cc1", if (interrupted) GccCompilerEngineContainmentRunKind.INTERRUPTED else GccCompilerEngineContainmentRunKind.FRESH_CONTROL,
            artifacts, runtime,
            GccCompilerEngineContainmentBudgets(if (interrupted) 900_000 else 180_000, 4L * 1024 * 1024 * 1024, 128),
            FullTreeDiskScratchPolicy(256L * 1024 * 1024, 1024L * 1024 * 1024, 1024, 16384),
        )
    }

    private fun retainFixtureEvidence(
        fixture: Path,
        intent: GccBundledOperationIntent,
        definition: GccCompilerEngineValidatedContainmentDefinition,
        execution: ByteArray,
        exportAssessment: ByteArray,
        assessment: GccCompletedRunAssessment,
        journalRoot: Path = fixture.resolve("journal"),
        plan: ByteArray? = null,
    ): Path {
        val parent = Path.of("build/contained-ghidra-evidence").toAbsolutePath().normalize()
        Files.createDirectories(parent)
        val destination = Files.createTempDirectory(parent, "authored-elf-")
        Files.setPosixFilePermissions(destination, PosixFilePermissions.fromString("rwx------"))
        var aggregate = 0L
        fun retain(relative: String, bytes: ByteArray) {
            aggregate = Math.addExact(aggregate, bytes.size.toLong())
            assertTrue(aggregate <= 64L * 1024 * 1024, "authored fixture evidence exceeds its aggregate capture bound")
            val path = destination.resolve(relative)
            Files.createDirectories(path.parent)
            readOnlyFile(path, bytes)
        }
        retain("intent.json", intent.canonicalBytes)
        retain("execution.json", execution)
        retain("export-assessment.json", exportAssessment)
        retain("authored.c", boundedRead(fixture.resolve("inputs/authored.c"), MAXIMUM_METADATA_BYTES))
        retain("authored.elf", boundedRead(fixture.resolve("inputs/authored.elf"), 8 * 1024 * 1024))
        retain("compiler-command.json", boundedRead(fixture.resolve("compiler-command.json"), MAXIMUM_METADATA_BYTES))
        retain("compiler.log", boundedRead(fixture.resolve("compiler.log"), MAXIMUM_METADATA_BYTES))
        val journal = journalRoot.resolve(".gcc-bundled-operation-${intent.operationId}")
        for (name in names(journal)) retain("journal/$name", boundedRead(journal.resolve(name), MAXIMUM_METADATA_BYTES))
        val reports = definition.outputLease.path.resolve("reports")
        for (name in listOf("program_model.json", "program_model.json.progress.json")) {
            retain("reports/$name", boundedRead(reports.resolve(name), if (name == "program_model.json") MAXIMUM_MODEL_BYTES else MAXIMUM_LOG_BYTES))
        }
        val command = OracleJson.parseCanonical(execution).jsonObject.getValue("execution").jsonObject
        val control = Path.of(command.getValue("controlDirectory").jsonPrimitive.content)
        assertEquals(definition.outputLease.path, control.parent)
        for (name in listOf("contained-command.stdout", "contained-command.stderr")) {
            retain("control-reports/$name", boundedRead(control.resolve("reports").resolve(name), MAXIMUM_LOG_BYTES))
        }
        if (plan != null) retain("module-plan.json", plan)
        val export = reports.resolve("program_model.json.export")
        retain("reports/program_model.json.export/state.json", boundedRead(export.resolve("state.json"), MAXIMUM_METADATA_BYTES))
        val batches = export.resolve("planning-batches")
        for (name in names(batches)) {
            retain("reports/program_model.json.export/planning-batches/$name", boundedRead(batches.resolve(name), MAXIMUM_MODEL_BYTES))
        }
        retain("fixture-evidence.json", OracleJson.canonicalBytes(JsonObject(mapOf(
            "provider" to JsonPrimitive("bundled-ghidra-contained-authored-elf-fixture-v1"),
            "benchmarkAccepted" to JsonPrimitive(false),
            "releaseEligible" to JsonPrimitive(false),
            "scratchReleased" to JsonPrimitive(false),
            "operationId" to JsonPrimitive(intent.operationId),
            "requestSha256" to JsonPrimitive(intent.requestSha256),
            "definitionSha256" to JsonPrimitive(OracleArtifacts.sha256(definition.canonicalBytes)),
            "executionReceiptSha256" to JsonPrimitive(OracleArtifacts.sha256(execution)),
            "modelSha256" to JsonPrimitive(assessment.programModelSha256),
            "functionCount" to JsonPrimitive(assessment.functionCount),
            "planningBatchCount" to JsonPrimitive(assessment.planningBatchCount),
            "diskDisposition" to JsonPrimitive("retained residue; trusted CI fixture-filesystem teardown only"),
        ))))
        println("Retained bounded authored fixture evidence: $destination")
        return destination
    }

    private fun assertCopiedExportRejectsIdentityAndLinks(
        fixture: Path,
        output: Path,
        artifacts: List<GccCompilerEngineContainmentArtifactIdentity>,
        assessment: GccCompletedRunAssessment,
    ) {
        val copied = privateDirectory(fixture.resolve("capture-copy"))
        val reports = privateDirectory(copied.resolve("reports"))
        val export = privateDirectory(reports.resolve("program_model.json.export"))
        val batches = privateDirectory(export.resolve("planning-batches"))
        val originalReports = output.resolve("reports")
        for (name in listOf("program_model.json", "program_model.json.progress.json")) {
            readOnlyFile(reports.resolve(name), boundedRead(originalReports.resolve(name), MAXIMUM_MODEL_BYTES))
        }
        val originalExport = originalReports.resolve("program_model.json.export")
        readOnlyFile(export.resolve("state.json"), boundedRead(originalExport.resolve("state.json"), MAXIMUM_METADATA_BYTES))
        val originalBatches = originalExport.resolve("planning-batches")
        for (name in names(originalBatches)) readOnlyFile(batches.resolve(name), boundedRead(originalBatches.resolve(name), MAXIMUM_MODEL_BYTES))
        LinuxFilesystemSyscalls.openRoot(copied).use { run ->
            LinuxFilesystemSyscalls.openDirectoryAt(run.fd, "reports").use { selected ->
                val valid = GccBundledExportCapture.capture(run, selected.identity, artifacts)
                assertEquals(assessment.programModelSha256, valid.assessment.programModelSha256)
                val wrongInput = artifacts.map { artifact ->
                    if (artifact.role == GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY) {
                        artifact.copy(sha256 = if (artifact.sha256 == "a".repeat(64)) "b".repeat(64) else "a".repeat(64))
                    } else artifact
                }
                val mismatch = assertFailsWith<IllegalArgumentException> { GccBundledExportCapture.capture(run, selected.identity, wrongInput) }
                assertTrue(mismatch.message.orEmpty().contains("inputSha256"))
                val fragment = batches.resolve(names(batches).single { it.endsWith(".functions.fragment") })
                val original = boundedRead(fragment, MAXIMUM_MODEL_BYTES)
                Files.delete(fragment)
                Files.createSymbolicLink(fragment, fixture.resolve("inputs/authored.c"))
                try {
                    assertFails { GccBundledExportCapture.capture(run, selected.identity, artifacts) }
                } finally {
                    Files.delete(fragment)
                    readOnlyFile(fragment, original)
                }
                assertEquals(assessment.programModelSha256, GccBundledExportCapture.capture(run, selected.identity, artifacts).assessment.programModelSha256)
            }
        }
    }

    private fun assumeLiveTools() {
        assumeTrue(System.getProperty("os.name") == "Linux", "contained Ghidra execution requires Linux")
        for (path in listOf("/usr/bin/cc", "/usr/bin/bwrap", "/usr/bin/prlimit", "/usr/bin/systemd-run", "/usr/bin/systemctl", "/usr/bin/busctl")) {
            assumeTrue(Files.isExecutable(Path.of(path)), "contained Ghidra fixture executable is unavailable: $path")
        }
        val uid = (Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toInt()
        val userRuntime = Path.of("/run/user/$uid")
        assumeTrue(Files.isDirectory(userRuntime, LinkOption.NOFOLLOW_LINKS) && Files.exists(userRuntime.resolve("bus")), "user-systemd bus is unavailable")
        assertNotNull(System.getProperty("decompengine.oracle.gcc.bootKeeperClasspathRoot"))
        assertNotNull(System.getProperty("decompengine.ghidra.provenanceArchive"))
    }

    private fun configuredDirectory(variable: String): Path {
        val value = System.getenv(variable)?.takeIf(String::isNotBlank)
        assumeTrue(value != null, "$variable is not provisioned")
        val path = Path.of(checkNotNull(value))
        assertTrue(path.isAbsolute && path.normalize() == path && path.toRealPath() == path)
        assertTrue(Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS))
        return path
    }

    private fun withRequiredProvisioning(action: () -> Unit) {
        try {
            action()
        } catch (unavailable: TestAbortedException) {
            if (listOf("DECOMP_REQUIRE_BUNDLED_GHIDRA_EXECUTION", "DECOMP_REQUIRE_BUNDLED_GHIDRA_RUNTIME", "DECOMP_REQUIRE_ORACLE_EXT4_SCRATCH").any {
                System.getenv(it) == "true"
            }) throw AssertionError("required bundled contained-execution fixtures are unavailable", unavailable)
            throw unavailable
        }
    }

    private fun privateDirectory(path: Path): Path = Files.createDirectory(path).also {
        Files.setPosixFilePermissions(it, PosixFilePermissions.fromString("rwx------"))
    }

    private fun readOnlyFile(path: Path, bytes: ByteArray): Path = Files.write(path, bytes).also {
        Files.setPosixFilePermissions(it, PosixFilePermissions.fromString("r--------"))
    }

    private fun names(path: Path): List<String> = Files.newDirectoryStream(path).use { entries ->
        val result = arrayListOf<String>()
        for (entry in entries) {
            check(result.size < 256) { "fixture directory exceeds its entry bound" }
            result += entry.fileName.toString()
        }
        result.sorted()
    }

    private fun boundedRead(path: Path, maximum: Int): ByteArray {
        assertTrue(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS), "fixture artifact is not a regular file: $path")
        return Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS).use { it.readNBytes(maximum + 1) }.also {
            assertTrue(it.size <= maximum, "fixture artifact exceeds its byte bound: $path")
        }
    }

    private fun sha256(path: Path): String {
        val digest = MessageDigest.getInstance("SHA-256")
        Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS).use { input ->
            val buffer = ByteArray(1024 * 1024)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                digest.update(buffer, 0, count)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    private companion object {
        const val OPERATION_ID = "3333333333333333333333333333333333333333333333333333333333333333"
        const val MAXIMUM_MODEL_BYTES = 16 * 1024 * 1024
        const val MAXIMUM_METADATA_BYTES = 1024 * 1024
        const val MAXIMUM_LOG_BYTES = 1024 * 1024
    }
}
