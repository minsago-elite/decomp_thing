package decompengine.project

import decompengine.agent.AgentWorkflowProgress
import decompengine.agent.AgentWorkflowPhase
import decompengine.analysis.AnalysisDeadline
import decompengine.analysis.BundledGhidra
import decompengine.analysis.BoundedAnalysisProcessLaunch
import decompengine.analysis.BoundedProgramModelAcquisitionProcess
import decompengine.analysis.GhidraAnalysisException
import decompengine.analysis.GhidraInvocation
import decompengine.analysis.GhidraPostScript
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlin.io.path.createDirectories
import kotlin.io.path.pathString
import kotlin.io.path.writeBytes
import kotlin.io.path.writeText

fun interface ProgramModelAnalyzer {
    fun analyze(binaryPath: Path, workDir: Path): RecoveredProgramModel
}

/** Binds requested export budgets without starting analysis or raising existing limits. */
interface ExportBudgetedProgramModelAnalyzer : ProgramModelAnalyzer {
    fun withExportBudgets(budgets: ReconstructionBudgets): ProgramModelAnalyzer
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
    val maximumDiagnosticBytesPerStream: Int = 16 * 1024 * 1024,
) {
    init {
        require(!wallClockTimeout.isZero && !wallClockTimeout.isNegative && wallClockTimeout <= Duration.ofHours(24)) {
            "Ghidra export timeout must be positive and at most 24 hours"
        }
        require(!terminationGrace.isNegative && terminationGrace <= Duration.ofSeconds(30)) {
            "Ghidra termination grace must be between zero and 30 seconds"
        }
        require(maximumDiagnosticBytesPerStream in 1..(16 * 1024 * 1024)) {
            "Ghidra diagnostic stream limit must be positive and at most 16 MiB"
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

class GhidraHeadlessProgramModelAnalyzer private constructor(
    private val commandFactory: (GhidraInvocation, (String) -> Unit) -> List<String>,
    private val limits: GhidraProgramModelExportLimits,
    private val analysisToolSha256: String,
    private val recoveryMode: GhidraProgramModelRecoveryMode,
    private val processStarter: (List<String>, Path) -> Process,
    private val requiresLaunchPermit: Boolean,
    private val processLaunch: BoundedAnalysisProcessLaunch,
    private val processTreeFactory: (Process, Duration) -> ExportProcessTree,
) : ExportBudgetedProgramModelAnalyzer {
    internal constructor(
        commandFactory: (GhidraInvocation) -> List<String>,
        limits: GhidraProgramModelExportLimits = GhidraProgramModelExportLimits(),
        analysisToolSha256: String = UNAUTHENTICATED_ANALYSIS_TOOL_SHA256,
        recoveryMode: GhidraProgramModelRecoveryMode = GhidraProgramModelRecoveryMode.FULL,
    ) : this({ invocation, _ -> commandFactory(invocation) }, limits, analysisToolSha256, recoveryMode, ::startExportProcess, false,
        EXPORT_PROCESS_LAUNCH, ::ExportProcessTree)

    internal constructor(
        commandFactory: (GhidraInvocation) -> List<String>,
        limits: GhidraProgramModelExportLimits,
        processStarter: (List<String>, Path) -> Process,
        requiresLaunchPermit: Boolean = false,
    ) : this({ invocation, _ -> commandFactory(invocation) }, limits,
        UNAUTHENTICATED_ANALYSIS_TOOL_SHA256, GhidraProgramModelRecoveryMode.FULL, processStarter, requiresLaunchPermit,
        EXPORT_PROCESS_LAUNCH, ::ExportProcessTree)

    constructor(
        limits: GhidraProgramModelExportLimits = GhidraProgramModelExportLimits(),
        analysisToolSha256: String = BundledGhidra.ARCHIVE_SHA256,
        recoveryMode: GhidraProgramModelRecoveryMode = GhidraProgramModelRecoveryMode.FULL,
    ) : this({ invocation, checkpoint ->
        BundledGhidra.locate().analysisCommandForOwnedLaunch(invocation, checkpoint)
    }, limits, analysisToolSha256, recoveryMode, ::startExportProcess, true, EXPORT_PROCESS_LAUNCH, ::ExportProcessTree)

    init {
        require(analysisToolSha256.matches(Regex("[0-9a-f]{64}"))) {
            "Ghidra analysis-tool identity must be a lowercase SHA-256 digest"
        }
    }

    override fun withExportBudgets(budgets: ReconstructionBudgets): GhidraHeadlessProgramModelAnalyzer =
        GhidraHeadlessProgramModelAnalyzer(
            commandFactory = commandFactory,
            limits = limits.copy(
                wallClockTimeout = minOf(limits.wallClockTimeout, Duration.ofMillis(budgets.exportWallClockMillis)),
                maximumResidentBytes = minOf(limits.maximumResidentBytes, budgets.exportMaximumResidentBytes),
            ),
            analysisToolSha256 = analysisToolSha256,
            recoveryMode = recoveryMode,
            processStarter = processStarter,
            requiresLaunchPermit = requiresLaunchPermit,
            processLaunch = processLaunch,
            processTreeFactory = processTreeFactory,
        )

    internal fun withProcessLifecycleForTests(
        controller: BoundedAnalysisProcessLaunch,
        treeFactory: (Process, Duration) -> ExportProcessTree,
    ): GhidraHeadlessProgramModelAnalyzer = GhidraHeadlessProgramModelAnalyzer(
        commandFactory = commandFactory,
        limits = limits,
        analysisToolSha256 = analysisToolSha256,
        recoveryMode = recoveryMode,
        processStarter = processStarter,
        requiresLaunchPermit = requiresLaunchPermit,
        processLaunch = controller,
        processTreeFactory = treeFactory,
    )

    override fun analyze(binaryPath: Path, workDir: Path): RecoveredProgramModel =
        analyzeInternal(binaryPath, workDir, false, null).first

    internal fun analyzeWithDeadline(binaryPath: Path, workDir: Path, deadline: AnalysisDeadline): RecoveredProgramModel =
        analyzeInternal(binaryPath, workDir, false, deadline).first

    fun analyzeWithCallSites(binaryPath: Path, workDir: Path): RecoveredProgramWithCallSites {
        val (model, calls) = analyzeInternal(binaryPath, workDir, true, null)
        return RecoveredProgramWithCallSites(model, checkNotNull(calls))
    }

    private fun analyzeInternal(
        binaryPath: Path,
        workDir: Path,
        includeCallSites: Boolean,
        parentDeadline: AnalysisDeadline?,
    ): Pair<RecoveredProgramModel, RecoveredCallSiteReceipt?> {
        val deadline = AnalysisDeadline.start(
            limits.wallClockTimeout.toNanos(), "Ghidra program recovery", parentDeadline,
            AnalysisDeadline.RECOVERY_TIMEOUT_ADVICE,
        )
        return deadline.enforceDuring("Ghidra program recovery") {
            deadline.checkpoint("before export preparation")
            val reports = workDir.resolve("reports").createDirectories()
            val scripts = workDir.resolve("scripts").createDirectories()
            deadline.checkpoint("before reading export scripts")
            val scriptBytes = javaClass.getResourceAsStream("/ghidra_scripts/ExportProgramModelOwned.java")
                ?.use { it.readBytes() } ?: error("bundled ExportProgramModelOwned.java is missing")
            deadline.checkpoint("after reading export script")
            scripts.resolve("ExportProgramModelOwned.java").writeBytes(scriptBytes)
            deadline.checkpoint("after writing export script")
            val exporterSha256 = sha256(scriptBytes)
            val output = reports.resolve("program_model.json")
            val modelCandidate = uniqueExportCandidate(output, "model")
            val callOutput = reports.resolve("program_model_calls.json")
            val callScriptBytes = if (includeCallSites) {
                require(!Files.exists(callOutput, LinkOption.NOFOLLOW_LINKS)) { "call-site output already exists" }
                javaClass.getResourceAsStream("/ghidra_scripts/ExportRecoveredCallSites.java")
                    ?.use { it.readBytes() } ?: error("bundled ExportRecoveredCallSites.java is missing")
            } else null
            deadline.checkpoint("after preparing call-site script")
            val callCandidate = callScriptBytes?.let { uniqueExportCandidate(callOutput, "calls") }
            callScriptBytes?.let { scripts.resolve("ExportRecoveredCallSites.java").writeBytes(it) }
            deadline.checkpoint("before creating export project")
            val project = workDir.resolve("ghidra_project").createDirectories()
            val postScripts = listOf(GhidraPostScript("ExportProgramModelOwned.java", listOf(
                exporterSha256, analysisToolSha256, recoveryMode.wireName, output.toAbsolutePath().normalize().pathString,
                OWNED_MODEL_CANDIDATE_ARGUMENT,
                modelCandidate.toAbsolutePath().normalize().pathString,
            ))) + if (callScriptBytes == null) emptyList() else listOf(
                GhidraPostScript("ExportRecoveredCallSites.java", listOf(
                    sha256(callScriptBytes), analysisToolSha256, modelCandidate.toAbsolutePath().normalize().pathString,
                    checkNotNull(callCandidate).toAbsolutePath().normalize().pathString,
                )),
            )
            deadline.checkpoint("before constructing export command")
            val command = commandFactory(GhidraInvocation(project, "archival_reconstruction", binaryPath, scripts, postScripts), deadline::checkpoint)
            deadline.checkpoint("after constructing export command")
            val exitCode = executeExport(command, workDir, reports, deadline,
                listOfNotNull(modelCandidate, callCandidate))
            deadline.checkpoint("before export result validation")
            require(exitCode == 0) {
                "Ghidra program recovery failed with exit code $exitCode; see ${reports.resolve("ghidra_stderr.log")}"
            }
            val modelBytes = readStableProgramModel(modelCandidate, deadline)
            val model = ProgramModelJson.readCanonical(modelBytes, deadline::checkpoint)
            deadline.checkpoint("after canonical model validation")
            val calls = callScriptBytes?.let { script ->
                val callLimits = RecoveredCallSiteLimits()
                val callCandidatePath = checkNotNull(callCandidate)
                fun requireRemainingTime() {
                    deadline.checkpoint("during call-site export validation")
                }
                requireRemainingTime()
                require(Files.isRegularFile(callCandidatePath, LinkOption.NOFOLLOW_LINKS)) {
                    "call-site export did not produce a regular candidate"
                }
                val digest = MessageDigest.getInstance("SHA-256")
                var bytes = 0L
                Files.newInputStream(callCandidatePath, java.nio.file.StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS).use { stream ->
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
                    callCandidatePath, digest.digest().joinToString("") { "%02x".format(it) },
                    RecoveredCallSiteBindings(model.inputSha256, sha256(modelBytes), sha256(script), analysisToolSha256),
                    callLimits,
                ) { requireRemainingTime() }.also { requireRemainingTime() }
            }
            deadline.checkpoint("before publishing validated export candidates")
            deadline.checkpoint("before publishing validated program model")
            moveExportCandidate(modelCandidate, output)
            if (callCandidate != null) {
                deadline.checkpoint("before publishing validated call-site evidence")
                moveExportCandidate(callCandidate, callOutput)
            }
            model to calls
        }
    }

    private fun executeExport(
        command: List<String>,
        workDir: Path,
        reports: Path,
        deadline: AnalysisDeadline,
        outputCandidates: List<Path>,
    ): Int {
        val remainingNanosAtLaunch = deadline.remainingNanos("before worker launch")
        val process = processLaunch.start(
            deadline::checkpoint,
            { processStarter(command, workDir) },
            { lateProcess -> stopLateExportProcess(lateProcess, limits.terminationGrace, processLaunch, outputCandidates) },
        )
        val processTree = processTreeFactory(process, limits.terminationGrace)
        val taskSettlements = ArrayList<AtomicBoolean>()
        val captureSettlements = ArrayList<AtomicBoolean>()
        val taskFailures = ConcurrentLinkedQueue<Throwable>()
        val peakResidentBytes = AtomicLong(0)
        val memoryExceeded = AtomicBoolean(false)
        val diagnosticsExceeded = AtomicBoolean(false)
        val tasks = ArrayList<CompletableFuture<*>>()
        var stdout: CompletableFuture<ByteArray>? = null
        var stderr: CompletableFuture<ByteArray>? = null
        var diagnosticsPublished = false
        var primaryFailure: Throwable? = null
        fun publishDiagnostics(stdoutBytes: ByteArray, stderrBytes: ByteArray, beforeWrite: () -> Unit = {}) {
            beforeWrite()
            reports.resolve("ghidra_stdout.log").writeBytes(stdoutBytes)
            beforeWrite()
            reports.resolve("ghidra_stderr.log").writeBytes(stderrBytes)
            beforeWrite()
            reports.resolve("ghidra_resource_usage.json").writeText(
                "{\"maximumResidentBytesLimit\":${limits.maximumResidentBytes}," +
                    "\"maximumResidentBytesObserved\":${peakResidentBytes.get()}," +
                    "\"wallClockMillisLimit\":${limits.wallClockTimeout.toMillis()}," +
                    "\"parentWallClockMillisLimit\":${deadline.parentMaximumMillis}," +
                    "\"remainingWallClockNanosAtLaunch\":$remainingNanosAtLaunch," +
                    "\"maximumDiagnosticBytesPerStream\":${limits.maximumDiagnosticBytesPerStream}," +
                    "\"stdoutBytesRetained\":${stdoutBytes.size},\"stderrBytesRetained\":${stderrBytes.size}," +
                    "\"diagnosticLimitExceeded\":${diagnosticsExceeded.get()}}\n",
            )
            diagnosticsPublished = true
        }
        try {
            deadline.checkpoint("after worker launch")
            if (requiresLaunchPermit) {
                // A newly started bundled worker stays inert until its handle is owned here.
                // The two-byte permit fits in the fresh stdin pipe without a child-side read.
                process.outputStream.write(byteArrayOf('1'.code.toByte(), '\n'.code.toByte()))
                process.outputStream.flush()
            }
            process.outputStream.close()
            val memoryMonitorFinished = AtomicBoolean(false)
            taskSettlements += memoryMonitorFinished
            captureSettlements += memoryMonitorFinished
            val memoryMonitor = CompletableFuture.runAsync {
                try {
                    while (process.isAlive) {
                        val observed = residentBytes(process)
                        peakResidentBytes.accumulateAndGet(observed, ::maxOf)
                        if (observed > limits.maximumResidentBytes) {
                            memoryExceeded.set(true)
                            processTree.terminate()
                            break
                        }
                        Thread.sleep(25)
                    }
                } catch (failure: Throwable) {
                    taskFailures.add(failure)
                    throw failure
                } finally {
                    memoryMonitorFinished.set(true)
                }
            }.also(tasks::add)
            fun capture(stream: java.io.InputStream): CompletableFuture<ByteArray> {
                val finished = AtomicBoolean(false)
                taskSettlements += finished
                captureSettlements += finished
                return CompletableFuture.supplyAsync {
                    try {
                        val bytes = stream.readNBytes(limits.maximumDiagnosticBytesPerStream + 1)
                        if (bytes.size > limits.maximumDiagnosticBytesPerStream) {
                            diagnosticsExceeded.set(true)
                            processTree.terminate()
                            bytes.copyOf(limits.maximumDiagnosticBytesPerStream)
                        } else bytes
                    } catch (failure: Throwable) {
                        taskFailures.add(failure)
                        throw failure
                    } finally {
                        finished.set(true)
                    }
                }.also(tasks::add)
            }
            val stdoutTask = capture(process.inputStream).also { stdout = it }
            val stderrTask = capture(process.errorStream).also { stderr = it }
            val completed = try {
                process.waitFor(deadline.remainingNanosOrZero(), TimeUnit.NANOSECONDS)
            } catch (interrupted: InterruptedException) {
                if (deadline.remainingNanosOrZero() == 0L) false else throw interrupted
            }
            if (!completed) processTree.terminate()
            fun <T> await(task: CompletableFuture<T>): T {
                while (true) {
                    val remainingNanos = processTree.remainingCleanupNanosOrNull()
                        ?: deadline.remainingNanosOrZero()
                    val pollNanos = minOf(remainingNanos, TimeUnit.MILLISECONDS.toNanos(100))
                    try {
                        return task.get(pollNanos, TimeUnit.NANOSECONDS)
                    } catch (timeout: java.util.concurrent.TimeoutException) {
                        if (task.isDone) return task.get()
                        if (remainingNanos == 0L) throw timeout
                    }
                }
            }
            val stdoutBytes = await(stdoutTask)
            val stderrBytes = await(stderrTask)
            await(memoryMonitor)
            publishDiagnostics(stdoutBytes, stderrBytes)
            if (memoryExceeded.get()) throw GhidraAnalysisException(
                "Ghidra program recovery exceeded ${limits.maximumResidentBytes} resident bytes; " +
                    "rerun with the same output directory to resume durable function checkpoints",
            )
            if (diagnosticsExceeded.get()) throw GhidraAnalysisException(
                "Ghidra program recovery exceeded ${limits.maximumDiagnosticBytesPerStream} diagnostic bytes per stream; " +
                    "rerun with the same output directory to resume durable function checkpoints",
            )
            if (!completed) {
                val expired = try {
                    deadline.checkpoint("while waiting for export completion")
                    null
                } catch (failure: GhidraAnalysisException) {
                    failure
                }
                throw GhidraAnalysisException(
                    "${expired?.message ?: "Ghidra export exceeded its wall-clock allowance"}; " +
                        "rerun with the same output directory to resume durable function checkpoints",
                    expired,
                )
            }
            deadline.checkpoint("after export diagnostics")
            return process.exitValue()
        } catch (failure: Throwable) {
            val reported = if (failure is java.util.concurrent.TimeoutException) {
                try {
                    deadline.checkpoint("while waiting for export output")
                    GhidraAnalysisException("Ghidra export diagnostic drain exceeded its allowance", failure)
                } catch (checkpointFailure: Throwable) {
                    checkpointFailure.addSuppressed(failure)
                    checkpointFailure
                }
            } else failure
            primaryFailure = reported
            throw reported
        } finally {
            var cleanupFailure: Throwable? = null
            var cleanupProblem: Throwable? = null
            var quarantineRequired = false
            var cleanupInterrupted = Thread.interrupted()
            fun cleanup(action: () -> Unit) {
                try { action() } catch (failure: Throwable) {
                    val previous = primaryFailure ?: cleanupFailure
                    if (previous == null) cleanupFailure = failure else previous.addSuppressed(failure)
                }
            }
            fun recordCleanupFailure(failure: Throwable) {
                if (cleanupProblem == null) cleanupProblem = failure
                quarantineRequired = true
                val previous = primaryFailure ?: cleanupFailure
                if (previous == null) cleanupFailure = failure
                else if (previous !== failure) previous.addSuppressed(failure)
            }
            val reportedTaskFailures = java.util.Collections.newSetFromMap(
                java.util.IdentityHashMap<Throwable, Boolean>(),
            )
            fun preserveTaskFailures() {
                taskFailures.forEach { failure ->
                    if (!reportedTaskFailures.add(failure)) return@forEach
                    val previous = primaryFailure ?: cleanupFailure
                    val captured = GhidraAnalysisException("Ghidra export monitor/capture task failed", failure)
                    if (previous == null) cleanupFailure = captured
                    else if (previous !== failure && previous.cause !== failure) previous.addSuppressed(captured)
                }
            }
            val treeResult = runCatching { processTree.terminate() }.getOrElse { failure ->
                ExportProcessCleanupResult(false, failure)
            }
            if (!treeResult.confirmedAbsent) {
                val failure = GhidraAnalysisException(
                    "Ghidra export cleanup could not prove absence of its retained process/handle inventory",
                    treeResult.failure,
                )
                recordCleanupFailure(failure)
            } else if (treeResult.failure != null) {
                recordCleanupFailure(treeResult.failure)
            }
            preserveTaskFailures()
            tasks.forEach { task -> cleanup { task.cancel(true) } }
            val streamCloseFailures = ConcurrentLinkedQueue<Throwable>()
            val streamSettlements = ArrayList<AtomicBoolean>()
            listOf(process.inputStream, process.errorStream, process.outputStream).forEach { stream ->
                val settled = AtomicBoolean(false)
                streamSettlements += settled
                taskSettlements += settled
                CompletableFuture.runAsync {
                    try { stream.close() } catch (failure: Throwable) {
                        streamCloseFailures.add(failure)
                        throw failure
                    } finally {
                        settled.set(true)
                    }
                }.also(tasks::add)
            }
            var taskCleanupInterrupted = false
            while (taskSettlements.any { !it.get() }) {
                val remaining = processTree.remainingCleanupNanosOrNull() ?: 0L
                if (remaining == 0L) break
                try {
                    TimeUnit.NANOSECONDS.sleep(minOf(remaining, TimeUnit.MILLISECONDS.toNanos(25)))
                } catch (_: InterruptedException) {
                    taskCleanupInterrupted = true
                }
            }
            val allSettlementsConfirmed = taskSettlements.all { it.get() }
            preserveTaskFailures()
            val captureTasksConfirmed = captureSettlements.all { it.get() }
            val streamClosuresConfirmed = streamSettlements.all { it.get() }
            if (!captureTasksConfirmed) {
                recordCleanupFailure(GhidraAnalysisException(
                    "Ghidra export cleanup could not prove bounded capture/monitor completion within its original window",
                ))
            }
            if (!streamClosuresConfirmed) {
                recordCleanupFailure(GhidraAnalysisException(
                    "Ghidra export cleanup could not prove bounded stream closure within its original window",
                ))
            }
            streamCloseFailures.forEach { failure ->
                recordCleanupFailure(GhidraAnalysisException("Ghidra export stream closure failed", failure))
            }
            if (quarantineRequired && cleanupProblem != null) {
                val retained = ExportProcessCleanupOwner(
                    processTree = processTree,
                    process = process,
                    tasks = tasks.toList(),
                    taskSettlements = taskSettlements.toList(),
                    taskFailures = taskFailures,
                    streams = listOf(process.inputStream, process.errorStream, process.outputStream),
                    outputCandidates = outputCandidates,
                )
                processLaunch.quarantineUnconfirmedCleanup(checkNotNull(cleanupProblem), retained)
            }
            if (treeResult.confirmedAbsent && allSettlementsConfirmed && primaryFailure != null && !diagnosticsPublished) {
                val stdoutTask = stdout
                val stderrTask = stderr
                if (stdoutTask != null && stderrTask != null) cleanup {
                    // The watchdog may interrupt the normal drain after the worker has timed out.
                    // Retain its bounded output before cancelling capture, without replacing the
                    // original failure or starting a fresh process-tree cleanup allowance.
                    fun remainingCleanup(): Long = (processTree.remainingCleanupNanosOrNull() ?: 0L).also {
                        if (it == 0L) throw java.util.concurrent.TimeoutException("export diagnostic cleanup allowance expired")
                    }
                    var interruptionRecorded = false
                    fun interrupted(failure: Throwable) {
                        cleanupInterrupted = true
                        if (!interruptionRecorded) {
                            primaryFailure?.addSuppressed(failure)
                            interruptionRecorded = true
                        }
                    }
                    fun <T> duringCleanup(action: (Long) -> T): T {
                        while (true) {
                            val remaining = remainingCleanup()
                            try {
                                return action(remaining)
                            } catch (failure: InterruptedException) {
                                interrupted(failure)
                            } catch (failure: java.nio.channels.ClosedByInterruptException) {
                                Thread.interrupted()
                                interrupted(failure)
                            }
                        }
                    }
                    val stdoutBytes = duringCleanup { stdoutTask.get(it, TimeUnit.NANOSECONDS) }
                    val stderrBytes = duringCleanup { stderrTask.get(it, TimeUnit.NANOSECONDS) }
                    // Each attempt opens fresh streams; an interrupt-closed channel is never reused.
                    duringCleanup { publishDiagnostics(stdoutBytes, stderrBytes) { remainingCleanup() } }
                }
            }
            val usagePath = reports.resolve("ghidra_resource_usage.json")
            if (primaryFailure is InterruptedException && !Files.exists(usagePath, LinkOption.NOFOLLOW_LINKS)) {
                cleanup {
                    usagePath.writeText(
                        "{\"maximumResidentBytesLimit\":${limits.maximumResidentBytes}," +
                            "\"maximumResidentBytesObserved\":${peakResidentBytes.get()}," +
                            "\"wallClockMillisLimit\":${limits.wallClockTimeout.toMillis()}," +
                            "\"parentWallClockMillisLimit\":${deadline.parentMaximumMillis}," +
                            "\"remainingWallClockNanosAtLaunch\":$remainingNanosAtLaunch," +
                            "\"maximumDiagnosticBytesPerStream\":${limits.maximumDiagnosticBytesPerStream}," +
                            "\"stdoutBytesRetained\":0,\"stderrBytesRetained\":0," +
                            "\"diagnosticLimitExceeded\":${diagnosticsExceeded.get()}}\n",
                    )
                }
            }
            if (taskCleanupInterrupted || treeResult.failure is InterruptedException) cleanupInterrupted = true
            if (cleanupInterrupted) Thread.currentThread().interrupt()
            cleanupFailure?.let { throw it }

        }
    }

    private fun readStableProgramModel(path: Path, deadline: AnalysisDeadline): ByteArray {
        return MODEL_ACQUISITION.read(path, path.toAbsolutePath().normalize().parent,
            limits.maximumProgramModelBytes, limits.maximumResidentBytes, deadline)
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

    companion object {
        private val EXPORT_PROCESS_LAUNCH = BoundedAnalysisProcessLaunch()
        private val MODEL_ACQUISITION = BoundedProgramModelAcquisitionProcess()

        internal const val UNAUTHENTICATED_ANALYSIS_TOOL_SHA256 =
            "0000000000000000000000000000000000000000000000000000000000000000"

        fun bundled(
            profile: ReconstructionProfile = GeneratedCMakeReconstructionProfile.descriptor,
            hostSafetyLimits: ReconstructionHostSafetyLimits = ReconstructionHostSafetyLimits.DEFAULT,
        ): GhidraHeadlessProgramModelAnalyzer {
            hostSafetyLimits.requireAllows(profile.budgets)
            return GhidraHeadlessProgramModelAnalyzer(GhidraProgramModelExportLimits.from(profile))
        }
    }
}

internal data class ExportProcessCleanupResult(val confirmedAbsent: Boolean, val failure: Throwable?)

/** References retained after unresolved cleanup prevent another launch from assuming capacity. */
private data class ExportProcessCleanupOwner(
    val processTree: ExportProcessTree,
    val process: Process,
    val tasks: List<CompletableFuture<*>>,
    val taskSettlements: List<AtomicBoolean>,
    val taskFailures: ConcurrentLinkedQueue<Throwable>,
    val streams: List<AutoCloseable>,
    val outputCandidates: List<Path>,
)

private const val OWNED_MODEL_CANDIDATE_ARGUMENT = "owned-model-candidate-v1"
        internal val EXPORT_CANDIDATE_NONCE = System.nanoTime().toULong().toString(16)
        internal val EXPORT_CANDIDATE_SEQUENCE = AtomicLong()

private fun uniqueExportCandidate(target: Path, kind: String): Path {
    require(kind.matches(Regex("[a-z]+")))
    val sequence = EXPORT_CANDIDATE_SEQUENCE.updateAndGet(Math::incrementExact)
    val candidate = target.resolveSibling(".${target.fileName}-$kind-$EXPORT_CANDIDATE_NONCE-${sequence.toString(16)}.candidate")
    require(!Files.exists(candidate, LinkOption.NOFOLLOW_LINKS)) { "export candidate path already exists" }
    return candidate
}

private fun moveExportCandidate(candidate: Path, target: Path) {
    try {
        Files.move(candidate, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
    } catch (unsupported: java.nio.file.AtomicMoveNotSupportedException) {
        Files.move(candidate, target, StandardCopyOption.REPLACE_EXISTING)
    }
}

/** One invocation-wide grace + force/wait window; only the retained observations are covered. */
internal class ExportProcessTree(
    private val process: Process,
    private val gracefulTermination: Duration,
    private val nanoTime: () -> Long = System::nanoTime,
    private val sleepNanos: (Long) -> Unit = { TimeUnit.NANOSECONDS.sleep(it) },
    private val descendantObservation: (ProcessHandle, (ProcessHandle) -> Unit) -> Unit = { root, retain ->
        root.descendants().use { stream -> stream.forEach { retain(it) } }
    },
) {
    private var terminationStartedNanos: Long? = null
    private var result: ExportProcessCleanupResult? = null
    private var rootHandle: ProcessHandle? = null
    private val observedHandles = LinkedHashMap<Long, ProcessHandle>()
    private var observationFailure: Throwable? = null

    @Synchronized
    fun terminate(): ExportProcessCleanupResult {
        result?.let { return it }
        val started = terminationStartedNanos ?: nanoTime().also { terminationStartedNanos = it }
        val graceNanos = gracefulTermination.toNanos()
        fun observe(stage: String) {
            try {
                val root = rootHandle ?: process.toHandle().also { rootHandle = it }
                descendantObservation(root) { handle ->
                    if (!observedHandles.containsKey(handle.pid())) {
                        if (observedHandles.size + 1 >= MAXIMUM_RETAINED_HANDLES) {
                            throw IllegalStateException("Ghidra export process inventory exceeded $MAXIMUM_RETAINED_HANDLES retained handles")
                        }
                        // Retain incrementally: if stream traversal fails after yielding handles,
                        // already-observed references remain signalable and available for cleanup.
                        // This is not process-group containment proof.
                        observedHandles[handle.pid()] = handle
                    }
                }
            } catch (failure: Throwable) {
                if (observationFailure == null) observationFailure = GhidraAnalysisException(
                    "Ghidra export process observation failed $stage", failure,
                ) else if (observationFailure !== failure) observationFailure?.addSuppressed(failure)
            }
        }
        fun knownHandles(): List<ProcessHandle> = observedHandles.values.toList()
        fun aliveOrUnknown(): Boolean {
            var alive = false
            try { alive = process.isAlive || alive } catch (failure: Throwable) {
                observationFailure = observationFailure ?: failure
            }
            val root = rootHandle
            if (root != null) try { alive = root.isAlive || alive } catch (failure: Throwable) {
                observationFailure = observationFailure ?: failure
            }
            for (handle in knownHandles()) try { alive = handle.isAlive || alive } catch (failure: Throwable) {
                observationFailure = observationFailure ?: failure
            }
            return alive || observationFailure != null
        }
        fun signal(force: Boolean) {
            knownHandles().asReversed().forEach { handle ->
                try { if (handle.isAlive) { if (force) handle.destroyForcibly() else handle.destroy() } }
                catch (failure: Throwable) { observationFailure = observationFailure ?: failure }
            }
            try { if (process.isAlive) { if (force) process.destroyForcibly() else process.destroy() } }
            catch (failure: Throwable) { observationFailure = observationFailure ?: failure }
            try {
                rootHandle?.let { if (it.isAlive) { if (force) it.destroyForcibly() else it.destroy() } }
            } catch (failure: Throwable) { observationFailure = observationFailure ?: failure }
        }
        fun remaining(allowance: Long): Long {
            val elapsed = nanoTime() - started
            return if (elapsed < 0 || elapsed >= allowance) 0L else allowance - elapsed
        }
        fun waitPhase(allowance: Long): Boolean {
            while (true) {
                observe("while reconciling retained descendants")
                if (!aliveOrUnknown()) return true
                val remaining = remaining(allowance)
                if (remaining == 0L) return false
                try { sleepNanos(minOf(remaining, POLL_NANOS)) }
                catch (failure: InterruptedException) {
                    if (observationFailure == null) observationFailure = failure
                    Thread.interrupted()
                }
            }
        }

        observe("before graceful termination")
        signal(force = false)
        val gracefullyAbsent = waitPhase(graceNanos)
        if (!gracefullyAbsent) {
            observe("before forced termination")
            signal(force = true)
        }
        val cleanupAllowance = saturatingAdd(graceNanos, FORCE_EXIT_WAIT_NANOS)
        val confirmed = if (gracefullyAbsent && observationFailure == null) true else
            waitPhase(cleanupAllowance) && observationFailure == null
        if (!confirmed) {
            // Make one final independent Process + root/retained-handle observation at the cutoff.
            observe("at the cleanup cutoff")
        }
        val stillObservedAlive = aliveOrUnknown()
        val cleanupFailure = observationFailure
        val result = ExportProcessCleanupResult(
            confirmedAbsent = confirmed && !stillObservedAlive && cleanupFailure == null,
            failure = cleanupFailure,
        )
        this.result = result
        return result
    }

    @Synchronized
    fun remainingCleanupNanosOrNull(): Long? {
        val started = terminationStartedNanos ?: return null
        val elapsed = nanoTime() - started
        val allowance = saturatingAdd(gracefulTermination.toNanos(), FORCE_EXIT_WAIT_NANOS)
        return if (elapsed < 0 || elapsed >= allowance) 0L else allowance - elapsed
    }

    internal fun retainedHandleCount(): Int = synchronized(this) { observedHandles.size + if (rootHandle == null) 0 else 1 }

    private fun saturatingAdd(start: Long, vararg nanos: Long): Long {
        var value = start
        for (amount in nanos) value = if (Long.MAX_VALUE - value < amount) Long.MAX_VALUE else value + amount
        return value
    }

    private companion object {
        const val MAXIMUM_RETAINED_HANDLES = 32
        val FORCE_EXIT_WAIT_NANOS: Long = TimeUnit.SECONDS.toNanos(5)
        val POLL_NANOS: Long = TimeUnit.MILLISECONDS.toNanos(25)
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
    private val reconstructor: ModuleReconstructor? = null,
    private val profile: ReconstructionProfile = GeneratedCMakeReconstructionProfile.descriptor,
    private val hostSafetyLimits: ReconstructionHostSafetyLimits = ReconstructionHostSafetyLimits.DEFAULT,
    private val progress: AgentWorkflowProgress = AgentWorkflowProgress.NONE,
) {
    init {
        hostSafetyLimits.requireAllows(profile.budgets)
    }

    private val adapter = ReconstructionAdapters.resolve(profile)

    fun reconstruct(binaryPath: Path, outputDir: Path): ArchivalReconstructionResult {
        if (Thread.interrupted()) throw InterruptedException("archival reconstruction cancelled")
        adapter.admitGeneration(outputDir.resolve("source-tree"), profile, reconstructor ?: adapter.defaultReconstructor())
        outputDir.createDirectories()
        val observedBehavior = ReconstructionExplorationInput.read(
            outputDir, profile.budgets.reconstructionMaximumContextCharacters,
        )
        val selectedAnalyzer = (analyzer as? ExportBudgetedProgramModelAnalyzer)
            ?.withExportBudgets(profile.budgets)
            ?: analyzer
        adapter.diagnostics.prepare(profile)
        progress.phase(AgentWorkflowPhase.ANALYZING)
        val model = selectedAnalyzer.analyze(binaryPath, outputDir.resolve("analysis"))
        val project = outputDir.resolve("source-tree")
        val progressPath = outputDir.resolve("reconstruction_progress.json")
        progressPath.writeText("{\"phase\":\"planning\",\"completed\":0,\"total\":0}\n")
        progress.phase(AgentWorkflowPhase.PLANNING)
        var moduleTotal = 0
        SourceTreeGenerator.generate(
            model,
            project,
            hostSafetyLimits = hostSafetyLimits,
            reconstructor = reconstructor,
            observedBehavior = observedBehavior,
            profile = profile,
            progress = progress,
        ) { completed, total, module ->
            moduleTotal = total
            progressPath.writeText("{\"phase\":\"modules\",\"completed\":$completed,\"total\":$total,\"module\":\"$module\"}\n")
        }
        progress.phase(AgentWorkflowPhase.BUILD_VALIDATING)
        val build = adapter.build(project, profile, hostSafetyLimits)
        val bundle = ArchivalPackager.create(
            project,
            outputDir.resolve("source-tree.zip"),
            ArchivalBundleLimits(
                maximumEntries = profile.budgets.archiveMaximumEntries,
                maximumFileBytes = profile.budgets.archiveMaximumFileBytes,
                maximumTotalBytes = profile.budgets.archiveMaximumTotalBytes,
            ),
            profile = profile,
            hostSafetyLimits = hostSafetyLimits,
        )
        val unresolvedEntities = requireNotNull(bundle.audit).unresolvedEntityIds
        val completeImplementation = !adapter.requiresUnresolvedOutput(profile) && unresolvedEntities.isEmpty()
        val implementationStatus = if (completeImplementation) "complete" else "unresolved"
        progressPath.writeText(
            "{\"phase\":\"$implementationStatus\",\"completed\":$moduleTotal,\"total\":$moduleTotal," +
                "\"unresolvedEntityCount\":${unresolvedEntities.size}}\n",
        )
        progress.phase(if (completeImplementation) AgentWorkflowPhase.COMPLETED else AgentWorkflowPhase.UNRESOLVED)
        outputDir.resolve("reconstruction.json").writeText(
            """
            {
              "inputSha256": "${model.inputSha256}",
              "project": "source-tree",
              "archive": "source-tree.zip",
              "archiveSha256": "${bundle.archiveSha256}",
              "profileId": "${profile.id}",
              "profileSha256": "${profile.sha256}",
              "archivePublication": ${bundle.publication?.toJson() ?: "null"},
              "moduleCount": $moduleTotal,
              "functionCount": ${model.functions.size},
              "globalCount": ${model.globals.size},
              "typeCount": ${model.types.size},
              "buildExitCode": ${build.returnCode},
              "implementationStatus": "$implementationStatus",
              "unresolvedEntityCount": ${unresolvedEntities.size}
            }
            """.trimIndent() + "\n",
        )
        return ArchivalReconstructionResult(project, build, bundle)
    }
}

private fun startExportProcess(command: List<String>, workDir: Path): Process =
    ProcessBuilder(command).directory(workDir.toFile()).start()

private fun stopLateExportProcess(
    process: Process,
    terminationGrace: Duration,
    processLaunch: BoundedAnalysisProcessLaunch,
    outputCandidates: List<Path>,
) {
    val interruptedOnEntry = Thread.interrupted()
    var failure: Throwable? = null
    fun cleanup(action: () -> Unit) {
        try { action() } catch (caught: Throwable) {
            val previous = failure
            if (previous == null) failure = caught else if (previous !== caught) previous.addSuppressed(caught)
        }
    }
    try {
        val processTree = ExportProcessTree(process, terminationGrace)
        val result = try { processTree.terminate() } catch (caught: Throwable) {
            ExportProcessCleanupResult(false, caught)
        }
        if (!result.confirmedAbsent) cleanup {
            throw GhidraAnalysisException(
                "late Ghidra export cleanup could not prove absence of its retained process/handle inventory",
                result.failure,
            )
        }
        cleanup { process.outputStream.close() }
        cleanup { process.inputStream.close() }
        cleanup { process.errorStream.close() }
        if (process.isAlive) cleanup { throw GhidraAnalysisException("late export worker did not stop within its cleanup allowance") }
        failure?.let {
            processLaunch.quarantineUnconfirmedCleanup(
                it,
                ExportProcessCleanupOwner(
                    processTree = processTree,
                    process = process,
                    tasks = emptyList(),
                    taskSettlements = emptyList(),
                    taskFailures = ConcurrentLinkedQueue(),
                    streams = listOf(process.inputStream, process.errorStream, process.outputStream),
                    outputCandidates = outputCandidates,
                ),
            )
            throw it
        }
    } finally {
        if (interruptedOnEntry) Thread.currentThread().interrupt()
    }
}
