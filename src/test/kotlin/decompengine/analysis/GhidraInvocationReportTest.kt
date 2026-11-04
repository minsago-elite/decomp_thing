package decompengine.analysis

import decompengine.jobs.elfFixture
import decompengine.project.GhidraHeadlessProgramModelAnalyzer
import decompengine.project.GhidraProgramModelExportLimits
import decompengine.project.RecoveredProgramModel
import decompengine.project.sha256
import java.nio.file.Path
import java.nio.file.Files
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.io.path.createDirectories
import kotlin.io.path.readText
import kotlin.io.path.writeBytes
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long

class GhidraInvocationReportTest {
    @Test
    fun `prepared commands snapshot mutable vectors and use a fixed redacted label`() {
        val source = mutableListOf("/fixture/java", "-Dsecret=never-report", "fixture.Worker", "release", "analyze", "/tmp/job")
        val prepared = PreparedGhidraCommand.controlledTest(source, 2, 4)
        source[2] = "changed.Worker"

        assertEquals("fixture.Worker", prepared.command[2])
        assertTrue(prepared.toString().contains("CONTROLLED_TEST_JAVA"))
        assertTrue(!prepared.toString().contains("secret"))
        assertFailsWith<UnsupportedOperationException> { (prepared.command as MutableList<String>)[0] = "mutated" }
    }

    @Test
    fun `custom commands have no qualified java layout`() {
        val prepared = PreparedGhidraCommand.custom(listOf("fixture.Worker", "secret"))

        assertEquals(GhidraCommandKind.CUSTOM, prepared.kind)
        assertEquals(null, prepared.mainClassIndex)
        assertEquals(null, prepared.analysisArgumentsIndex)
        assertTrue(!prepared.toString().contains("secret"))
    }

    @Test
    fun `bounded snapshot rejects oversize and malformed invocation values`() {
        assertFailsWith<IllegalArgumentException> {
            PreparedGhidraCommand.custom(listOf("x".repeat(65_537)))
        }
        assertFailsWith<IllegalArgumentException> {
            PreparedGhidraCommand.custom(listOf("bad\u0000value"))
        }
        assertFailsWith<IllegalArgumentException> {
            PreparedGhidraCommand.custom(List(257) { "x" })
        }
        assertFailsWith<IllegalArgumentException> {
            PreparedGhidraCommand.custom(listOf("\uD800"))
        }
        val boundary = PreparedGhidraCommand.custom(listOf("x".repeat(65_536), "y".repeat(65_536)))
        PreparedGhidraCommand.validateWorkingDirectory("z".repeat(0), boundary) {}
        assertFailsWith<IllegalArgumentException> {
            PreparedGhidraCommand.validateWorkingDirectory("z", boundary) {}
        }
        val directoryBoundary = PreparedGhidraCommand.custom(listOf("x".repeat(65_536)))
        PreparedGhidraCommand.validateWorkingDirectory("z".repeat(65_536), directoryBoundary) {}
        assertFailsWith<IllegalArgumentException> {
            PreparedGhidraCommand.validateWorkingDirectory("z".repeat(65_537), directoryBoundary) {}
        }
        assertFailsWith<IllegalArgumentException> {
            PreparedGhidraCommand.validateWorkingDirectory("z\uDFFF", PreparedGhidraCommand.custom(emptyList())) {}
        }
    }

    @Test
    fun `report reflects the command and working directory passed to the process starter`() {
        val root = temporaryRoot("invocation-receipt-")
        try {
            val inputBytes = elfFixture()
            val input = root.toRealPath().resolve("input.elf").also { it.writeBytes(inputBytes) }
            val work = root.resolve("analysis")
            assertTrue(GhidraProjectLocation.accepts(work.resolve("ghidra_project")))
            val vector = mutableListOf("/fixture/java", "-Dfixture=private", "fixture.Worker", "/fixture/release",
                "await-parent-launch", "analyze")
            val prepared = PreparedGhidraCommand.controlledTest(vector, 2, 5)
            vector[1] = "--mutated-after-preparation=must-not-reach-boundary"
            var captured: List<String>? = null
            var capturedDirectory: Path? = null
            var observedExit: Int? = null
            val adapter = GhidraHeadlessProgramModelAnalyzer.forInvocationReceiptTests(
                prepared, GhidraProgramModelExportLimits(),
            ) { command, directory ->
                captured = command.toList()
                capturedDirectory = directory
                val candidate = Path.of(command.last())
                candidate.parent.createDirectories()
                candidate.writeText(RecoveredProgramModel(inputSha256 = sha256(inputBytes), functions = emptyList()).toJson())
                GhidraInvocationTestProcess { observedExit = it }
            }
            val analysis = GhidraJvmAnalyzer(adapter).analyze(input, work)
            val report = Json.parseToJsonElement(analysis.reportPath.readText()).jsonObject
            val invocation = report.getValue("invocation").jsonObject
            val exact = checkNotNull(captured)

            assertEquals("controlled-test-java", invocation.getValue("commandKind").jsonPrimitive.content)
            assertEquals("injected", invocation.getValue("processStarterKind").jsonPrimitive.content)
            assertEquals(exact.first(), invocation.getValue("executable").jsonPrimitive.content)
            assertEquals("-Dfixture=private", exact[1])
            assertEquals(exact[2], invocation.getValue("mainClass").jsonPrimitive.content)
            assertEquals(exact.drop(3), invocation.getValue("workerArguments").jsonArray.map { it.jsonPrimitive.content })
            assertEquals(exact.drop(5), analysis.args)
            assertEquals(2, invocation.getValue("analysisArgumentOffset").jsonPrimitive.content.toInt())
            assertEquals(work.resolve("ghidra_project").toString(), exact[6])
            assertEquals("ExportProgramModelOwned.java", exact[10])
            assertEquals("6", exact[11])
            assertEquals(capturedDirectory.toString(), invocation.getValue("workingDirectory").jsonPrimitive.content)
            assertEquals(observedExit, invocation.getValue("exitCode").jsonPrimitive.content.toInt())
            assertEquals("fixture.Worker", analysis.mainClass)
            assertTrue(!analysis.reportPath.readText().contains("-Dfixture=private"))
        } finally {
            root.toFile().deleteRecursively()
        }
    }

    @Test
    fun `custom commands are captured but their command contents are withheld`() {
        val root = temporaryRoot("custom-invocation-receipt-")
        try {
            val inputBytes = elfFixture()
            val input = root.toRealPath().resolve("input.elf").also { it.writeBytes(inputBytes) }
            val secret = "--shell-payload=private-test-value"
            val factoryVector = AtomicReference<MutableList<String>>()
            val adapter = GhidraHeadlessProgramModelAnalyzer(
                commandFactory = { invocation ->
                    mutableListOf("/bin/true", secret, BundledGhidra.WORKER_CLASS).apply {
                        addAll(invocation.arguments())
                        factoryVector.set(this)
                    }
                },
                limits = GhidraProgramModelExportLimits(),
                processStarter = { command, directory ->
                    val boundaryExecutable = command.first()
                    factoryVector.get().set(0, "mutated-after-command-factory")
                    assertEquals("/bin/true", boundaryExecutable)
                    assertEquals("/bin/true", command.first())
                    val candidate = Path.of(command.last())
                    candidate.parent.createDirectories()
                    candidate.writeText(RecoveredProgramModel(inputSha256 = sha256(inputBytes), functions = emptyList()).toJson())
                    GhidraInvocationTestProcess()
                },
            )

            val analysis = GhidraJvmAnalyzer(adapter).analyze(input, root.resolve("analysis"))
            val reportText = analysis.reportPath.readText()
            val invocation = Json.parseToJsonElement(reportText).jsonObject.getValue("invocation").jsonObject

            assertEquals("custom", invocation.getValue("commandKind").jsonPrimitive.content)
            assertEquals("withheld-custom-command", invocation.getValue("commandDisclosure").jsonPrimitive.content)
            assertTrue("executable" !in invocation && "mainClass" !in invocation && "workerArguments" !in invocation)
            assertTrue(!reportText.contains(secret))
            assertEquals("", analysis.mainClass)
            assertTrue(analysis.args.isEmpty())
        } finally {
            root.toFile().deleteRecursively()
        }
    }

    @Test
    fun `concurrent calls on one analyzer keep captured commands and directories independent`() {
        val root = temporaryRoot("concurrent-invocation-receipt-")
        val executor = Executors.newFixedThreadPool(2)
        try {
            val firstBytes = elfFixture()
            val secondBytes = elfFixture() + byteArrayOf(0x51)
            assertTrue(sha256(firstBytes) != sha256(secondBytes))
            val firstInput = root.toRealPath().resolve("first.elf").also { it.writeBytes(firstBytes) }
            val secondInput = root.toRealPath().resolve("second.elf").also { it.writeBytes(secondBytes) }
            val dotWork = root.resolve(".decomp_engine/jobs/first/reports/analysis")
            val normalWork = root.resolve("jobs/second/reports/analysis")
            assertTrue(GhidraProjectLocation.accepts(normalWork.resolve("ghidra_project")))
            assertTrue(!GhidraProjectLocation.accepts(dotWork.resolve("ghidra_project")))
            val hashesByDirectory = mapOf(dotWork.toAbsolutePath().toString() to sha256(firstBytes),
                normalWork.toAbsolutePath().toString() to sha256(secondBytes))
            val captured = ConcurrentHashMap<String, List<String>>()
            val bothStarted = CountDownLatch(2)
            val releaseFirst = CountDownLatch(1)
            val releaseSecond = CountDownLatch(1)
            val observedExits = ConcurrentHashMap<String, Int>()
            val prepared = PreparedGhidraCommand.controlledTest(
                listOf("/fixture/java", "-Dfixture=private", "fixture.Worker", "/fixture/release", "await-parent-launch", "analyze"),
                2, 5,
            )
            val adapter = GhidraHeadlessProgramModelAnalyzer.forInvocationReceiptTests(
                prepared, GhidraProgramModelExportLimits(),
            ) { command, directory ->
                val key = directory.toAbsolutePath().toString()
                captured[key] = command.toList()
                val candidate = Path.of(command.last())
                candidate.parent.createDirectories()
                candidate.writeText(RecoveredProgramModel(
                    inputSha256 = checkNotNull(hashesByDirectory[key]), functions = emptyList(),
                ).toJson())
                bothStarted.countDown()
                val release = if (key == dotWork.toAbsolutePath().toString()) releaseFirst else releaseSecond
                check(release.await(10, TimeUnit.SECONDS)) { "concurrent test did not release both starters" }
                GhidraInvocationTestProcess { observedExits[key] = it }
            }
            val analyzer = GhidraJvmAnalyzer(adapter)
            val first = executor.submit<GhidraAnalysis> { analyzer.analyze(firstInput, dotWork) }
            val second = executor.submit<GhidraAnalysis> { analyzer.analyze(secondInput, normalWork) }
            val overlapped = bothStarted.await(10, TimeUnit.SECONDS)
            assertTrue(overlapped, "both process-starter boundaries must overlap")
            releaseSecond.countDown()
            val completedSecond = second.get(30, TimeUnit.SECONDS)
            assertTrue(!first.isDone, "second call must finish before first is released")
            releaseFirst.countDown()
            val analyses = listOf(first.get(30, TimeUnit.SECONDS), completedSecond)

            analyses.forEach { analysis ->
                val work = analysis.reportsDir.parent.toAbsolutePath().toString()
                val report = Json.parseToJsonElement(analysis.reportPath.readText()).jsonObject
                val invocation = report.getValue("invocation").jsonObject
                val command = checkNotNull(captured[work])
                assertEquals(command.first(), invocation.getValue("executable").jsonPrimitive.content)
                assertEquals(command.drop(3), invocation.getValue("workerArguments").jsonArray.map { it.jsonPrimitive.content })
                assertEquals(work, invocation.getValue("workingDirectory").jsonPrimitive.content)
                assertEquals(observedExits.getValue(work), invocation.getValue("exitCode").jsonPrimitive.content.toInt())
                assertEquals(2, invocation.getValue("analysisArgumentOffset").jsonPrimitive.content.toInt())
                assertEquals(if (work == dotWork.toAbsolutePath().toString()) "/proc/self/cwd/ghidra_project"
                    else normalWork.resolve("ghidra_project").toString(), command[6])
                assertEquals("ExportProgramModelOwned.java", command[10])
                assertEquals("6", command[11])
                assertEquals("owned-model-candidate-v1", command[16])
            }
        } finally {
            executor.shutdownNow()
            assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS), "concurrent receipt callers must settle")
            root.toFile().deleteRecursively()
        }
    }

    @Test
    fun `sequential reuse preserves earlier report evidence and records each latest call`() {
        val root = temporaryRoot("reused-invocation-receipt-")
        try {
            val bytes = elfFixture()
            val input = root.toRealPath().resolve("input.elf").also { it.writeBytes(bytes) }
            val work = root.resolve("analysis")
            val latestCommand = AtomicReference<List<String>>()
            val template = PreparedGhidraCommand.controlledTest(
                listOf("/fixture/java", "-Dfixture=private", "fixture.Worker", "/fixture/release", "await-parent-launch", "analyze"),
                2, 5,
            )
            val adapter = GhidraHeadlessProgramModelAnalyzer.forInvocationReceiptTests(
                template, GhidraProgramModelExportLimits(),
            ) { command, directory ->
                latestCommand.set(command.toList())
                val candidate = Path.of(command.last())
                candidate.parent.createDirectories()
                candidate.writeText(RecoveredProgramModel(inputSha256 = sha256(bytes), functions = emptyList()).toJson())
                GhidraInvocationTestProcess()
            }
            val analyzer = GhidraJvmAnalyzer(adapter)

            val firstAnalysis = analyzer.analyze(input, work)
            val firstReport = Json.parseToJsonElement(firstAnalysis.reportPath.readText()).jsonObject
            val firstInvocation = firstReport.getValue("invocation").jsonObject
            val firstCommand = checkNotNull(latestCommand.get())
            val other = analyzer.analyze(input, root.resolve("other-analysis"))
            val otherCommand = checkNotNull(latestCommand.get())
            assertEquals(otherCommand.drop(3), Json.parseToJsonElement(other.reportPath.readText()).jsonObject
                .getValue("invocation").jsonObject.getValue("workerArguments").jsonArray.map { it.jsonPrimitive.content })
            val secondAnalysis = analyzer.analyze(input, work)
            val secondInvocation = Json.parseToJsonElement(secondAnalysis.reportPath.readText()).jsonObject.getValue("invocation").jsonObject
            val secondCommand = checkNotNull(latestCommand.get())

            assertEquals(firstCommand.drop(3), firstInvocation.getValue("workerArguments").jsonArray.map { it.jsonPrimitive.content })
            assertEquals(secondCommand.drop(3), secondInvocation.getValue("workerArguments").jsonArray.map { it.jsonPrimitive.content })
            assertTrue(firstCommand.last() != secondCommand.last(), "each export must retain a unique candidate argument")
            assertEquals(firstCommand.drop(3), firstInvocation.getValue("workerArguments").jsonArray.map { it.jsonPrimitive.content })
            assertEquals(firstCommand.drop(5), firstAnalysis.args)
            assertTrue(otherCommand.last() != secondCommand.last())
        } finally {
            root.toFile().deleteRecursively()
        }
    }

    @Test
    fun `UTF16 checkpoint thresholds cannot be skipped by boundary straddling pairs`() {
        val straddling = CharArray(65_536) { 'x' }.also { chars ->
            for (boundary in 1024 until chars.size step 1024) {
                chars[boundary - 1] = '\uD83D'; chars[boundary] = '\uDE00'
            }
        }.concatToString()
        for (value in listOf(straddling, "\uD83D\uDE00".repeat(32768))) {
            var calls = 0
            PreparedGhidraCommand.custom(listOf(value)) { calls++ }
            assertTrue(calls >= 65, "valid supplementary characters must not skip chunk checkpoints")
            var directoryCalls = 0
            PreparedGhidraCommand.validateWorkingDirectory(value, PreparedGhidraCommand.custom(emptyList())) { directoryCalls++ }
            assertTrue(directoryCalls >= 64)
            calls = 0
            assertFailsWith<InterruptedException> {
                PreparedGhidraCommand.custom(listOf(value)) { if (++calls == 3) throw InterruptedException("authored cancellation") }
            }
            assertEquals(3, calls)
            directoryCalls = 0
            assertFailsWith<InterruptedException> {
                PreparedGhidraCommand.validateWorkingDirectory(value, PreparedGhidraCommand.custom(emptyList())) {
                    if (++directoryCalls == 2) throw InterruptedException("authored cancellation")
                }
            }
        }
        for (value in listOf("\uD800", "\uDC00", "x".repeat(1023) + "\uD800x")) {
            assertFailsWith<IllegalArgumentException> { PreparedGhidraCommand.custom(listOf(value)) }
            assertFailsWith<IllegalArgumentException> {
                PreparedGhidraCommand.validateWorkingDirectory(value, PreparedGhidraCommand.custom(emptyList())) {}
            }
        }
        val prepared = PreparedGhidraCommand.controlledTest(listOf("java", "Worker", "analyze", "a"), 1, 2)
        val slice = prepared.command.subList(2, 4)
        assertFailsWith<UnsupportedOperationException> { (slice as MutableList<String>)[0] = "changed" }
        assertEquals(listOf("analyze", "a"), slice)
    }

    @Test
    fun `adapter refuses count length aggregate layout and cancellation before starter admission`() {
        val root = temporaryRoot("admission-")
        try {
            val input = root.toRealPath().resolve("input.elf").also { it.writeBytes(elfFixture()) }
            val work = root.resolve("analysis")
            var starts = 0
            val invalid = listOf(
                List(257) { "x" }, listOf("PRIVATE".padEnd(65537, 'x')),
                listOf("x".repeat(65536), "y".repeat(65536)), listOf("PRIVATE\u0000"),
                listOf("PRIVATE\uD800"), listOf("PRIVATE\uDC00"),
            )
            invalid.forEach { vector ->
                val adapter = GhidraHeadlessProgramModelAnalyzer({ vector }, GhidraProgramModelExportLimits(), processStarter = { _, _ ->
                    starts++; GhidraInvocationTestProcess()
                })
                val failure = assertFailsWith<IllegalArgumentException> { adapter.analyze(input, work) }
                assertTrue(!failure.message.orEmpty().contains("PRIVATE"))
                assertTrue(failure.message.orEmpty().startsWith("Ghidra invocation"))
            }
            for ((main, analyze) in listOf(0 to 2, 1 to 1, 4 to 2, 1 to 9)) {
                val adapter = GhidraHeadlessProgramModelAnalyzer.forInvocationReceiptFactoryTests({ _, checkpoint ->
                    PreparedGhidraCommand.controlledTest(listOf("java", "Worker", "analyze"), main, analyze) { checkpoint("layout") }
                }) { _, _ -> starts++; GhidraInvocationTestProcess() }
                assertEquals("Ghidra invocation command layout is invalid",
                    assertFailsWith<IllegalArgumentException> { adapter.analyze(input, work) }.message)
            }
            val cancellation = GhidraHeadlessProgramModelAnalyzer.forInvocationReceiptFactoryTests({ _, checkpoint ->
                var chunks = 0
                PreparedGhidraCommand.controlledTest(listOf("java", "Worker", "analyze", "x".repeat(65536)), 1, 2) {
                    if (++chunks == 10) Thread.currentThread().interrupt()
                    checkpoint("controlled command chunk")
                }
            }) { _, _ -> starts++; GhidraInvocationTestProcess() }
            try { assertFailsWith<InterruptedException> { cancellation.analyze(input, work) } }
            finally { Thread.interrupted() }
            assertEquals(0, starts)
            assertTrue(!Files.exists(work.resolve("reports/ghidra_analysis.json")))

            val remaining = 131072 - work.toAbsolutePath().toString().length
            val accepted = listOf(List(256) { "x" }, listOf("x".repeat(65536)),
                listOf("x".repeat(65536), "y".repeat(remaining - 65536)))
            accepted.forEach { vector ->
                var candidate: Path? = null
                val adapter = GhidraHeadlessProgramModelAnalyzer({ invocation ->
                    candidate = Path.of(invocation.postScripts.single().arguments.last()); vector
                }, GhidraProgramModelExportLimits(), processStarter = { command, _ ->
                    assertEquals(vector, command); starts++
                    checkNotNull(candidate).writeText(RecoveredProgramModel(inputSha256 = sha256(elfFixture()), functions = emptyList()).toJson())
                    GhidraInvocationTestProcess()
                })
                adapter.analyze(input, work)
            }
            assertEquals(3, starts)
            val over = listOf("x".repeat(65536), "y".repeat(remaining - 65536 + 1))
            val adapter = GhidraHeadlessProgramModelAnalyzer({ over }, GhidraProgramModelExportLimits(), processStarter = { _, _ ->
                starts++; GhidraInvocationTestProcess()
            })
            assertFailsWith<IllegalArgumentException> { adapter.analyze(input, work) }
            assertEquals(3, starts)
        } finally { root.toFile().deleteRecursively() }
    }

    @Test
    fun `qualified receipt escaping privacy ceiling and prior report survive failed publication`() {
        val root = temporaryRoot("escaped-receipt-")
        try {
            val bytes = elfFixture()
            val input = root.toRealPath().resolve("input.elf").also { it.writeBytes(bytes) }
            val template = PreparedGhidraCommand.controlledTest(listOf("/fixture/java", "Worker\"\n\\",
                "\u0001".repeat(65536), "\u0002".repeat(60000), "await-parent-launch", "analyze"), 1, 5)
            val adapter = GhidraHeadlessProgramModelAnalyzer.forInvocationReceiptTests(template) { command, _ ->
                Path.of(command.last()).writeText(RecoveredProgramModel(inputSha256 = sha256(bytes), functions = emptyList()).toJson())
                GhidraInvocationTestProcess()
            }
            val work = root.resolve("analysis")
            val analysis = GhidraJvmAnalyzer(adapter).analyze(input, work)
            val prior = Files.readAllBytes(analysis.reportPath)
            assertTrue(prior.last() == '\n'.code.toByte())
            assertTrue(prior.size in 750000..(1024 * 1024))
            assertEquals(java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(analysis.reportPath))
            val json = Json.parseToJsonElement(prior.toString(Charsets.UTF_8)).jsonObject
            assertEquals(template.command[1], json.getValue("invocation").jsonObject.getValue("mainClass").jsonPrimitive.content)
            assertEquals(1024 * 1024L, json.getValue("reportPublication").jsonObject.getValue("maximumBytes").jsonPrimitive.long)
            val failing = GhidraJvmAnalyzer(adapter, decompengine.binary.BoundedElfMetadataLimits(), BoundedElfMetadataInspectionProcess()) {
                throw java.io.IOException("authored qualified receipt publication failure")
            }
            kotlin.test.assertFails { failing.analyze(input, work) }
            kotlin.test.assertContentEquals(prior, Files.readAllBytes(analysis.reportPath))
        } finally { root.toFile().deleteRecursively() }
    }

    @Test
    fun `successful budget and lifecycle clones preserve receipt classification`() {
        val root = temporaryRoot("clone-receipt-")
        try {
            val bytes = elfFixture()
            val input = root.toRealPath().resolve("input.elf").also { it.writeBytes(bytes) }
            val template = PreparedGhidraCommand.controlledTest(listOf("java", "Worker", "release", "gate", "analyze"), 1, 4)
            val adapter = GhidraHeadlessProgramModelAnalyzer.forInvocationReceiptTests(template) { command, _ ->
                Path.of(command.last()).writeText(RecoveredProgramModel(inputSha256 = sha256(bytes), functions = emptyList()).toJson())
                GhidraInvocationTestProcess()
            }
            val clones = listOf(adapter,
                adapter.withExportBudgets(decompengine.project.GeneratedCMakeReconstructionProfile.descriptor.budgets),
                adapter.withStreamCloseSubmitterForTests { java.util.concurrent.CompletableFuture.runAsync(it) },
                adapter.withAnalysisTaskExecutorForTests(java.util.concurrent.ForkJoinPool.commonPool()),
                adapter.withProcessLifecycleForTests(BoundedAnalysisProcessLaunch(), { process, grace -> decompengine.project.ExportProcessTree(process, grace) }))
            clones.forEachIndexed { i, clone ->
                val result = clone.analyzeWithInvocationReceipt(input, root.resolve("work-$i"),
                    AnalysisDeadline.start(TimeUnit.SECONDS.toNanos(10), "clone control"))
                assertEquals(GhidraCommandKind.CONTROLLED_TEST_JAVA, result.receipt!!.prepared.kind)
                assertEquals(GhidraProcessStarterKind.INJECTED, result.receipt.starterKind)
                assertEquals(0, result.receipt.exitCode)
            }
        } finally { root.toFile().deleteRecursively() }
    }

    @Test
    fun `custom default and injected starters keep truthful classification after budget clone`() {
        val root = temporaryRoot("custom-starter-")
        try {
            val bytes = elfFixture()
            val input = root.toRealPath().resolve("input.elf").also { it.writeBytes(bytes) }
            val factory: (GhidraInvocation) -> List<String> = { invocation ->
                Path.of(invocation.postScripts.single().arguments.last()).writeText(
                    RecoveredProgramModel(inputSha256 = sha256(bytes), functions = emptyList()).toJson())
                listOf("/bin/true")
            }
            val adapters = listOf(GhidraHeadlessProgramModelAnalyzer(factory) to GhidraProcessStarterKind.DEFAULT_PROCESS_BUILDER,
                GhidraHeadlessProgramModelAnalyzer(factory, GhidraProgramModelExportLimits(), processStarter = { _, _ ->
                    GhidraInvocationTestProcess()
                }) to GhidraProcessStarterKind.INJECTED)
            adapters.forEachIndexed { index, (adapter, expected) ->
                val clone = adapter.withExportBudgets(decompengine.project.GeneratedCMakeReconstructionProfile.descriptor.budgets)
                val receipt = clone.analyzeWithInvocationReceipt(input, root.resolve("work-$index"),
                    AnalysisDeadline.start(TimeUnit.SECONDS.toNanos(10), "custom clone")).receipt!!
                assertEquals(GhidraCommandKind.CUSTOM, receipt.prepared.kind)
                assertEquals(expected, receipt.starterKind)
                assertEquals(null, receipt.prepared.mainClassIndex)
                assertEquals(null, receipt.prepared.analysisArgumentsIndex)
            }
        } finally { root.toFile().deleteRecursively() }
    }

    private fun temporaryRoot(prefix: String): Path {
        val parent = Path.of("").toAbsolutePath().normalize()
            .resolve("build/orchestration/ghidra-invocation-report-tests").createDirectories()
        val real = Files.createTempDirectory(parent, prefix)
        val relative = Path.of("").toAbsolutePath().normalize().relativize(real)
        return Path.of("/proc", ProcessHandle.current().pid().toString(), "cwd").resolve(relative).also {
            assertTrue(GhidraProjectLocation.accepts(it.resolve("analysis/ghidra_project")))
            assertEquals(real.toRealPath(), it.toRealPath())
        }
    }
}
