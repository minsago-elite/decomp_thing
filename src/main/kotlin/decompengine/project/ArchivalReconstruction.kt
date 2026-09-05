package decompengine.project

import decompengine.analysis.GhidraAnalysisException
import decompengine.agent.AgentWorkflowProgress
import decompengine.agent.AgentWorkflowPhase
import decompengine.analysis.BundledGhidra
import decompengine.analysis.GhidraInvocation
import decompengine.analysis.GhidraPostScript
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.BasicFileAttributes
import java.security.MessageDigest
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlin.io.path.createDirectories
import kotlin.io.path.pathString
import kotlin.io.path.readText
import kotlin.io.path.writeBytes
import kotlin.io.path.writeText

fun interface ProgramModelAnalyzer {
    fun analyze(binaryPath: Path, workDir: Path): RecoveredProgramModel
}

data class RecoveredProgramWithCallSites(
    val programModel: RecoveredProgramModel,
    val callSites: RecoveredCallSiteReceipt,
)

data class GhidraProgramModelExportLimits(
    val wallClockTimeout: Duration = Duration.ofMinutes(10),
    val terminationGrace: Duration = Duration.ofSeconds(5),
    val maximumResidentBytes: Long = 4L * 1024 * 1024 * 1024,
    val maximumProgramModelBytes: Long = 512L * 1024 * 1024,
) {
    init {
        require(!wallClockTimeout.isZero && !wallClockTimeout.isNegative && wallClockTimeout <= Duration.ofHours(24)) {
            "Ghidra export timeout must be positive and at most 24 hours"
        }
        require(!terminationGrace.isNegative && terminationGrace <= Duration.ofSeconds(30)) {
            "Ghidra termination grace must be between zero and 30 seconds"
        }
        require(maximumResidentBytes > 0) { "Ghidra resident-memory limit must be positive" }
        require(maximumProgramModelBytes in 1..(512L * 1024 * 1024)) {
            "Ghidra program-model byte limit must be positive and at most 512 MiB"
        }
    }

    companion object {
        fun from(profile: ReconstructionProfile): GhidraProgramModelExportLimits =
            GhidraProgramModelExportLimits(
                wallClockTimeout = Duration.ofMillis(profile.budgets.exportWallClockMillis),
                maximumResidentBytes = profile.budgets.exportMaximumResidentBytes,
            )
    }
}

class GhidraHeadlessProgramModelAnalyzer internal constructor(
    private val commandFactory: (GhidraInvocation) -> List<String>,
    private val limits: GhidraProgramModelExportLimits = GhidraProgramModelExportLimits(),
    private val analysisToolSha256: String = UNAUTHENTICATED_ANALYSIS_TOOL_SHA256,
    private val recoveryMode: GhidraProgramModelRecoveryMode = GhidraProgramModelRecoveryMode.FULL,
) : ProgramModelAnalyzer {
    constructor(
        limits: GhidraProgramModelExportLimits = GhidraProgramModelExportLimits(),
        analysisToolSha256: String = BundledGhidra.ARCHIVE_SHA256,
        recoveryMode: GhidraProgramModelRecoveryMode = GhidraProgramModelRecoveryMode.FULL,
    ) : this({ BundledGhidra.locate().analysisCommand(it) }, limits, analysisToolSha256, recoveryMode)

    init {
        require(analysisToolSha256.matches(Regex("[0-9a-f]{64}"))) {
            "Ghidra analysis-tool identity must be a lowercase SHA-256 digest"
        }
    }

    override fun analyze(binaryPath: Path, workDir: Path): RecoveredProgramModel =
        analyzeInternal(binaryPath, workDir, false).first

    fun analyzeWithCallSites(binaryPath: Path, workDir: Path): RecoveredProgramWithCallSites {
        val (model, calls) = analyzeInternal(binaryPath, workDir, true)
        return RecoveredProgramWithCallSites(model, checkNotNull(calls))
    }

    private fun analyzeInternal(
        binaryPath: Path,
        workDir: Path,
        includeCallSites: Boolean,
    ): Pair<RecoveredProgramModel, RecoveredCallSiteReceipt?> {
        val startedNanos = System.nanoTime()
        val reports = workDir.resolve("reports").createDirectories()
        val scripts = workDir.resolve("scripts").createDirectories()
        val scriptBytes = javaClass.getResourceAsStream("/ghidra_scripts/ExportProgramModel.java")
            ?.use { it.readBytes() } ?: error("bundled ExportProgramModel.java is missing")
        scripts.resolve("ExportProgramModel.java").writeBytes(scriptBytes)
        val exporterSha256 = sha256(scriptBytes)
        val output = reports.resolve("program_model.json")
        val callOutput = reports.resolve("program_model_calls.json")
        val callScriptBytes = if (includeCallSites) {
            require(!Files.exists(callOutput, LinkOption.NOFOLLOW_LINKS)) { "call-site output already exists" }
            javaClass.getResourceAsStream("/ghidra_scripts/ExportRecoveredCallSites.java")
                ?.use { it.readBytes() } ?: error("bundled ExportRecoveredCallSites.java is missing")
        } else null
        callScriptBytes?.let { scripts.resolve("ExportRecoveredCallSites.java").writeBytes(it) }
        val project = workDir.resolve("ghidra_project").createDirectories()
        val postScripts = listOf(GhidraPostScript("ExportProgramModel.java", listOf(
            exporterSha256, analysisToolSha256, recoveryMode.wireName, output.toAbsolutePath().normalize().pathString,
        ))) + if (callScriptBytes == null) emptyList() else listOf(
            GhidraPostScript("ExportRecoveredCallSites.java", listOf(
                sha256(callScriptBytes), analysisToolSha256, output.toAbsolutePath().normalize().pathString,
                callOutput.toAbsolutePath().normalize().pathString,
            )),
        )
        val command = commandFactory(GhidraInvocation(project, "archival_reconstruction", binaryPath, scripts, postScripts))
        val process = ProcessBuilder(command)
            .directory(workDir.toFile())
            .start()
        val peakResidentBytes = AtomicLong(0)
        val memoryExceeded = AtomicBoolean(false)
        val memoryMonitor = CompletableFuture.runAsync {
            while (process.isAlive) {
                val observed = residentBytes(process)
                peakResidentBytes.accumulateAndGet(observed, ::maxOf)
                if (observed > limits.maximumResidentBytes) {
                    memoryExceeded.set(true)
                    terminateProcessTree(process, limits.terminationGrace)
                    break
                }
                Thread.sleep(25)
            }
        }
        val stdout = CompletableFuture.supplyAsync { process.inputStream.bufferedReader().readText() }
        val stderr = CompletableFuture.supplyAsync { process.errorStream.bufferedReader().readText() }
        val completed = process.waitFor(limits.wallClockTimeout.toMillis(), TimeUnit.MILLISECONDS)
        if (!completed) {
            terminateProcessTree(process, limits.terminationGrace)
        }
        val exitCode = if (completed) process.exitValue() else -1
        reports.resolve("ghidra_stdout.log").writeText(stdout.join())
        reports.resolve("ghidra_stderr.log").writeText(stderr.join())
        memoryMonitor.join()
        reports.resolve("ghidra_resource_usage.json").writeText(
            "{\"maximumResidentBytesLimit\":${limits.maximumResidentBytes}," +
                "\"maximumResidentBytesObserved\":${peakResidentBytes.get()}," +
                "\"wallClockMillisLimit\":${limits.wallClockTimeout.toMillis()}}\n",
        )
        if (memoryExceeded.get()) {
            throw GhidraAnalysisException(
                "Ghidra program recovery exceeded ${limits.maximumResidentBytes} resident bytes; " +
                    "rerun with the same output directory to resume durable function checkpoints",
            )
        }
        if (!completed) {
            throw GhidraAnalysisException(
                "Ghidra program recovery exceeded ${limits.wallClockTimeout.toSeconds()} seconds; " +
                    "rerun with the same output directory to resume durable function checkpoints",
            )
        }
        require(exitCode == 0 && Files.isRegularFile(output, LinkOption.NOFOLLOW_LINKS)) {
            "Ghidra program recovery failed with exit code $exitCode; see ${reports.resolve("ghidra_stderr.log")}"
        }
        val modelBytes = readStableProgramModel(output)
        val model = ProgramModelJson.readCanonical(modelBytes)
        val calls = callScriptBytes?.let { script ->
            val callLimits = RecoveredCallSiteLimits()
            fun requireRemainingTime() {
                check(!Thread.currentThread().isInterrupted) { "call-site export validation interrupted" }
                check(System.nanoTime() - startedNanos < limits.wallClockTimeout.toNanos()) {
                    "call-site export and validation exceeded the analysis wall-clock budget"
                }
            }
            requireRemainingTime()
            require(Files.isRegularFile(callOutput, LinkOption.NOFOLLOW_LINKS)) { "call-site export did not produce a regular file" }
            val digest = MessageDigest.getInstance("SHA-256")
            var bytes = 0L
            Files.newInputStream(callOutput, java.nio.file.StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS).use { stream ->
                val buffer = ByteArray(64 * 1024)
                while (true) {
                    requireRemainingTime()
                    val count = stream.read(buffer)
                    if (count < 0) break
                    bytes = Math.addExact(bytes, count.toLong())
                    require(bytes <= callLimits.maximumInputBytes) { "call-site export exceeds its input byte bound" }
                    digest.update(buffer, 0, count)
                }
            }
            RecoveredCallSites.read(
                callOutput, digest.digest().joinToString("") { "%02x".format(it) },
                RecoveredCallSiteBindings(model.inputSha256, sha256(modelBytes), sha256(script), analysisToolSha256),
                callLimits,
            ) { requireRemainingTime() }.also { requireRemainingTime() }
        }
        return model to calls
    }

    private fun readStableProgramModel(path: Path): ByteArray {
        val before = Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
        require(before.isRegularFile && before.size() in 1..limits.maximumProgramModelBytes) {
            "Ghidra program model exceeds its authenticated parser bound"
        }
        require(before.size() <= Int.MAX_VALUE) { "Ghidra program model cannot be represented by the bounded parser" }
        val bytes = Files.readAllBytes(path)
        val after = Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
        require(
            after.isRegularFile && before.fileKey() == after.fileKey() && before.size() == after.size() &&
                before.lastModifiedTime() == after.lastModifiedTime() && bytes.size.toLong() == before.size()
        ) { "Ghidra program model changed while being read" }
        return bytes
    }

    private fun residentBytes(process: Process): Long {
        val handles = process.toHandle().descendants().toList() + process.toHandle()
        return handles.distinctBy { it.pid() }.sumOf { handle ->
            runCatching {
                Files.readAllLines(Path.of("/proc/${handle.pid()}/status"))
                    .firstOrNull { it.startsWith("VmRSS:") }
                    ?.split(Regex("\\s+"))
                    ?.getOrNull(1)
                    ?.toLong()
                    ?.let { Math.multiplyExact(it, 1024L) }
                    ?: 0L
            }.getOrDefault(0L)
        }
    }

    private fun terminateProcessTree(process: Process, grace: Duration) {
        val handles = (process.toHandle().descendants().toList().asReversed() + process.toHandle()).distinct()
        handles.forEach { if (it.isAlive) it.destroy() }
        val deadline = System.nanoTime() + grace.toNanos()
        handles.forEach { handle ->
            val remaining = deadline - System.nanoTime()
            if (handle.isAlive && remaining > 0) {
                runCatching { handle.onExit().get(remaining, TimeUnit.NANOSECONDS) }
            }
        }
        handles.forEach { if (it.isAlive) it.destroyForcibly() }
        handles.forEach { handle -> if (handle.isAlive) runCatching { handle.onExit().get(5, TimeUnit.SECONDS) } }
    }

    companion object {
        internal const val UNAUTHENTICATED_ANALYSIS_TOOL_SHA256 =
            "0000000000000000000000000000000000000000000000000000000000000000"

        fun bundled(
            profile: ReconstructionProfile = GeneratedCMakeReconstructionProfile.descriptor,
        ): GhidraHeadlessProgramModelAnalyzer = GhidraHeadlessProgramModelAnalyzer(GhidraProgramModelExportLimits.from(profile))
    }
}

enum class GhidraProgramModelRecoveryMode(val wireName: String) {
    FULL("full"),
    PLANNING("planning"),
    ;

    companion object {
        fun fromWireName(value: String): GhidraProgramModelRecoveryMode = entries.singleOrNull { it.wireName == value }
            ?: throw IllegalArgumentException("unsupported Ghidra program-model recovery mode: $value")
    }
}

data class ArchivalReconstructionResult(
    val projectDir: Path,
    val build: BuildReport,
    val bundle: ArchivalBundle,
)

class ArchivalReconstructionService(
    private val analyzer: ProgramModelAnalyzer,
    private val reconstructor: ModuleReconstructor = EvidenceModuleReconstructor(),
    private val profile: ReconstructionProfile = GeneratedCMakeReconstructionProfile.descriptor,
    hostSafetyLimits: ReconstructionHostSafetyLimits = ReconstructionHostSafetyLimits(profile.budgets),
    private val progress: AgentWorkflowProgress = AgentWorkflowProgress.NONE,
) {
    init {
        hostSafetyLimits.requireAllows(profile.budgets)
    }

    fun reconstruct(binaryPath: Path, outputDir: Path): ArchivalReconstructionResult {
        outputDir.createDirectories()
        progress.phase(AgentWorkflowPhase.ANALYZING)
        val model = analyzer.analyze(binaryPath, outputDir.resolve("analysis"))
        val project = outputDir.resolve("source-tree")
        val progressPath = outputDir.resolve("reconstruction_progress.json")
        progressPath.writeText("{\"phase\":\"planning\",\"completed\":0,\"total\":0}\n")
        progress.phase(AgentWorkflowPhase.PLANNING)
        var moduleTotal = 0
        val observedBehavior = outputDir.resolve("exploration.json").takeIf { Files.isRegularFile(it) }?.readText()
        val planner = DeterministicModulePlanner(
            maximumFunctionsPerModule = profile.budgets.maximumFunctionsPerModule,
            layout = profile.layout,
            maximumEntities = profile.budgets.plannerMaximumEntities,
            maximumDependencyEdges = profile.budgets.plannerMaximumDependencyEdges,
            maximumWorkUnits = profile.budgets.plannerMaximumWorkUnits,
        )
        SourceTreeGenerator.generate(
            model,
            project,
            planner = planner,
            reconstructor = reconstructor,
            observedBehavior = observedBehavior,
            profile = profile,
            progress = progress,
        ) { completed, total, module ->
            moduleTotal = total
            progressPath.writeText("{\"phase\":\"modules\",\"completed\":$completed,\"total\":$total,\"module\":\"$module\"}\n")
        }
        progress.phase(AgentWorkflowPhase.BUILD_VALIDATING)
        val build = MakeProjectBuilder.build(
            project,
            ProjectBuildConfiguration(
                makeExecutable = profile.adapterConfiguration["build-executable"]?.singleOrNull() ?: "make",
                compilerExecutable = profile.adapterConfiguration["compiler-driver"]?.singleOrNull() ?: "gcc",
                cFlags = profile.adapterConfiguration["compiler-flags"] ?: ProjectBuildConfiguration().cFlags,
                wallClockTimeoutMillis = profile.budgets.buildWallClockMillis,
                maximumOutputBytes = profile.budgets.buildMaximumOutputBytes,
            ),
        )
        val bundle = ArchivalPackager.create(
            project,
            outputDir.resolve("source-tree.zip"),
            ArchivalBundleLimits(
                maximumEntries = profile.budgets.archiveMaximumEntries,
                maximumFileBytes = profile.budgets.archiveMaximumFileBytes,
                maximumTotalBytes = profile.budgets.archiveMaximumTotalBytes,
            ),
            profile,
        )
        progressPath.writeText("{\"phase\":\"complete\",\"completed\":$moduleTotal,\"total\":$moduleTotal}\n")
        progress.phase(if (build.returnCode == 0) AgentWorkflowPhase.COMPLETED
            else AgentWorkflowPhase.UNRESOLVED)
        outputDir.resolve("reconstruction.json").writeText(
            """
            {
              "inputSha256": "${model.inputSha256}",
              "project": "source-tree",
              "archive": "source-tree.zip",
              "archiveSha256": "${bundle.archiveSha256}",
              "profileId": "${profile.id}",
              "profileSha256": "${profile.sha256}",
              "moduleCount": ${planner.plan(model).modules.size},
              "functionCount": ${model.functions.size},
              "globalCount": ${model.globals.size},
              "typeCount": ${model.types.size},
              "buildExitCode": ${build.returnCode}
            }
            """.trimIndent() + "\n",
        )
        return ArchivalReconstructionResult(project, build, bundle)
    }
}
