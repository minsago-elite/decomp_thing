package decompengine.oracle.gcc

import decompengine.oracle.core.OracleArtifactLimits
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
import decompengine.project.DeterministicModulePlanner
import decompengine.project.ModulePlan
import decompengine.project.ProgramModelAnalyzer
import decompengine.project.RecoveredProgramModel
import decompengine.project.RecoveryStatus
import decompengine.project.writeProjectEvidenceAtomically
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.security.MessageDigest
import java.time.Duration
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlin.io.path.createDirectories
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive

class GccCompilerEnginePlanningException(message: String, cause: Throwable? = null) :
    IllegalStateException(message, cause)

data class GccCompilerEnginePlanningResult(
    val engineId: String,
    val programModelPath: Path,
    val programModelSha256: String,
    val modulePlanPath: Path,
    val modulePlanSha256: String,
    val evidencePath: Path,
    val evidenceSha256: String,
    val wallClockMillis: Long,
    val maximumResidentBytesObserved: Long,
)

/** Agent-free authenticated export and exact-ownership planning for the A10 scale benchmark. */
class GccCompilerEnginePlanningService(private val analyzer: ProgramModelAnalyzer) {
    fun plan(
        suite: GccCompilerEngineSuite,
        engineId: String,
        strippedArtifactPath: Path,
        outputDirectory: Path,
    ): GccCompilerEnginePlanningResult {
        val output = prepareOutputDirectory(outputDirectory)
        val engine = suite.engine(engineId)
        val started = System.nanoTime()
        val monitor = ProcessTreeResourceMonitor(
            maximumResidentBytes = suite.budgets.exportMaximumResidentBytes,
            maximumWallClockMillis = suite.budgets.exportWallClockMillis,
        )
        var primaryFailure: Throwable? = null
        try {
            val artifact = engine.authenticateStrippedArtifact(strippedArtifactPath)
            val model = try {
                analyzer.analyze(artifact.path, output.resolve("analysis"))
            } catch (failure: Throwable) {
                if (monitor.wallClockExceeded) {
                    throw GccCompilerEnginePlanningException(
                        "GCC $engineId export exceeded ${suite.budgets.exportWallClockMillis} milliseconds",
                        failure,
                    )
                }
                if (monitor.exceeded) {
                    throw GccCompilerEnginePlanningException(
                        "GCC $engineId export exceeded ${suite.budgets.exportMaximumResidentBytes} resident bytes",
                        failure,
                    )
                }
                throw failure
            }
            if (model.inputSha256 != artifact.sha256) {
                throw GccCompilerEnginePlanningException("GCC $engineId program model does not bind the authenticated input")
            }
            requireWithinBudgets(started, suite, monitor, "export")

            val profile = suite.reconstructionProfile()
            val modulePlan = DeterministicModulePlanner(
                maximumFunctionsPerModule = profile.budgets.maximumFunctionsPerModule,
                layout = profile.layout,
                maximumEntities = suite.budgets.plannerMaximumEntities,
                maximumDependencyEdges = suite.budgets.plannerMaximumDependencyEdges,
                maximumWorkUnits = suite.budgets.plannerMaximumWorkUnits,
            ).plan(model)
            requireExactOwnership(model, modulePlan)
            requireWithinBudgets(started, suite, monitor, "ownership planning")

            // Detect substitution between authentication and Ghidra/planner completion.
            engine.authenticateStrippedArtifact(artifact.path)
            val programModelPath = output.resolve("analysis/reports/program_model.json")
            val programModel = digestStableArtifact(programModelPath, MAXIMUM_PROGRAM_MODEL_BYTES, "program model")
            val planPath = output.resolve("planning/module_plan.json")
            planPath.parent.createDirectories()
            stableDirectory(planPath.parent, "module-plan directory")
            val planBytes = modulePlan.toJson().toByteArray(Charsets.UTF_8)
            if (planBytes.size !in 1..MAXIMUM_MODULE_PLAN_BYTES) {
                throw GccCompilerEnginePlanningException("module plan exceeds its bounded artifact limit")
            }
            publishDeterministic(planPath, planBytes, "module plan")
            val planArtifact = digestStableArtifact(planPath, MAXIMUM_MODULE_PLAN_BYTES.toLong(), "module plan")
            if (planArtifact.sha256 != OracleArtifacts.sha256(planBytes)) {
                throw GccCompilerEnginePlanningException("published module plan differs from deterministic planner output")
            }

            val progress = readExportProgress(output.resolve("analysis/reports/program_model.json.progress.json"), model)
            monitor.close()
            requireWithinBudgets(started, suite, monitor, "completed export and ownership planning")
            val elapsedMillis = elapsedMillis(started)
            val evidencePath = output.resolve("planning/compiler_engine_plan_evidence.json")
            val evidence = renderEvidence(
                suite = suite,
                engine = engine,
                reconstructionProfileSha256 = profile.sha256,
                programModel = programModel,
                modulePlan = planArtifact,
                model = model,
                moduleCount = modulePlan.modules.size,
                progress = progress,
                wallClockMillis = elapsedMillis,
                maximumResidentBytesObserved = monitor.peakResidentBytes,
            )
            val published = try {
                OracleArtifacts.publishAtomically(evidencePath, evidence, OracleArtifactLimits(MAXIMUM_EVIDENCE_BYTES))
            } catch (failure: Exception) {
                throw GccCompilerEnginePlanningException("cannot publish compiler-engine planning evidence", failure)
            }
            return GccCompilerEnginePlanningResult(
                engineId = engineId,
                programModelPath = programModel.path,
                programModelSha256 = programModel.sha256,
                modulePlanPath = planArtifact.path,
                modulePlanSha256 = planArtifact.sha256,
                evidencePath = evidencePath,
                evidenceSha256 = published.sha256,
                wallClockMillis = elapsedMillis,
                maximumResidentBytesObserved = monitor.peakResidentBytes,
            )
        } catch (failure: Throwable) {
            primaryFailure = failure
            throw failure
        } finally {
            try {
                monitor.close()
            } catch (closeFailure: Throwable) {
                if (primaryFailure != null) primaryFailure.addSuppressed(closeFailure) else throw closeFailure
            }
        }
    }

    private fun requireWithinBudgets(
        started: Long,
        suite: GccCompilerEngineSuite,
        monitor: ProcessTreeResourceMonitor,
        phase: String,
    ) {
        if (monitor.exceeded || monitor.peakResidentBytes > suite.budgets.exportMaximumResidentBytes) {
            throw GccCompilerEnginePlanningException(
                "GCC compiler-engine $phase exceeded ${suite.budgets.exportMaximumResidentBytes} resident bytes",
            )
        }
        if (monitor.wallClockExceeded) {
            throw GccCompilerEnginePlanningException(
                "GCC compiler-engine $phase exceeded ${suite.budgets.exportWallClockMillis} milliseconds",
            )
        }
        val elapsed = elapsedMillis(started)
        if (elapsed > suite.budgets.exportWallClockMillis) {
            throw GccCompilerEnginePlanningException(
                "GCC compiler-engine $phase exceeded ${suite.budgets.exportWallClockMillis} milliseconds",
            )
        }
    }

    private fun requireExactOwnership(model: RecoveredProgramModel, plan: ModulePlan) {
        val assignedFunctions = plan.modules.flatMap { it.functionIds }
        val assignedGlobals = plan.modules.flatMap { it.globalIds }
        val assignedTypes = plan.modules.flatMap { it.typeIds }
        if (
            assignedFunctions.size != model.functions.size || assignedFunctions.toSet() != model.functions.mapTo(hashSetOf()) { it.id } ||
            assignedGlobals.size != model.globals.size || assignedGlobals.toSet() != model.globals.mapTo(hashSetOf()) { it.id } ||
            assignedTypes.size != model.types.size || assignedTypes.toSet() != model.types.mapTo(hashSetOf()) { it.id }
        ) {
            throw GccCompilerEnginePlanningException("module plan does not assign every recovered entity exactly once")
        }
    }

    private fun readExportProgress(path: Path, model: RecoveredProgramModel): ExportProgress {
        val bytes = try {
            OracleArtifacts.read(path, OracleArtifactLimits(MAXIMUM_PROGRESS_BYTES)).bytes
        } catch (failure: Exception) {
            throw GccCompilerEnginePlanningException("cannot read completed Ghidra export progress", failure)
        }
        val root = try {
            OracleJson.parse(bytes, evidenceJsonLimits(MAXIMUM_PROGRESS_BYTES)) as? JsonObject
                ?: throw GccCompilerEnginePlanningException("Ghidra export progress root is not an object")
        } catch (failure: GccCompilerEnginePlanningException) {
            throw failure
        } catch (failure: Exception) {
            throw GccCompilerEnginePlanningException("Ghidra export progress is not strict bounded JSON", failure)
        }
        if (root.keys != EXPORT_PROGRESS_KEYS) {
            throw GccCompilerEnginePlanningException("Ghidra export progress has an unexpected shape")
        }
        if (root.longField("schemaVersion") != 1L) {
            throw GccCompilerEnginePlanningException("Ghidra export progress has an unsupported schema version")
        }
        val progress = ExportProgress(
            functions = root.longField("total"),
            completed = root.longField("completed"),
            recovered = root.longField("recovered"),
            partial = root.longField("partial"),
            failed = root.longField("failed"),
            reused = root.longField("reused"),
        )
        if (root.stringField("phase") != "complete" || root["currentFunction"] !is JsonNull) {
            throw GccCompilerEnginePlanningException("Ghidra export progress is not complete")
        }
        val recovered = model.functions.count { it.status == RecoveryStatus.RECOVERED }.toLong()
        val partial = model.functions.count { it.status == RecoveryStatus.PARTIAL }.toLong()
        val failed = model.functions.count { it.status == RecoveryStatus.FAILED }.toLong()
        val unsupported = model.functions.count { it.status !in EXPORT_RECOVERY_STATUSES }
        if (
            progress.functions != model.functions.size.toLong() || progress.completed != progress.functions ||
            progress.recovered != recovered || progress.partial != partial || progress.failed != failed || unsupported != 0 ||
            progress.reused !in 0..progress.functions
        ) {
            throw GccCompilerEnginePlanningException("Ghidra export progress counts differ from the program model")
        }
        return progress
    }

    private fun renderEvidence(
        suite: GccCompilerEngineSuite,
        engine: GccCompilerEngine,
        reconstructionProfileSha256: String,
        programModel: StableArtifact,
        modulePlan: StableArtifact,
        model: RecoveredProgramModel,
        moduleCount: Int,
        progress: ExportProgress,
        wallClockMillis: Long,
        maximumResidentBytesObserved: Long,
    ): ByteArray {
        val fields = linkedMapOf<String, kotlinx.serialization.json.JsonElement>(
            "schemaVersion" to JsonPrimitive(1),
            "complete" to JsonPrimitive(true),
            "benchmark" to JsonObject(
                mapOf(
                    "id" to JsonPrimitive(suite.id),
                    "version" to JsonPrimitive(suite.version),
                    "target" to JsonPrimitive(suite.target),
                    "profileSha256" to JsonPrimitive(suite.profileSha256),
                    "sourceRevision" to JsonPrimitive(suite.sourceRevision),
                ),
            ),
            "implementation" to JsonObject(
                mapOf(
                    "runtime" to JsonPrimitive("kotlin-jvm"),
                    "exporterId" to JsonPrimitive(suite.analysis.exporterId),
                    "exporterVersion" to JsonPrimitive(suite.analysis.exporterVersion),
                    "exporterSha256" to JsonPrimitive(suite.analysis.exporterSha256),
                    "ghidraVersion" to JsonPrimitive(suite.analysis.ghidraVersion),
                    "ghidraArchiveSha256" to JsonPrimitive(suite.analysis.ghidraArchive.sha256),
                    "plannerId" to JsonPrimitive(suite.analysis.plannerId),
                    "plannerVersion" to JsonPrimitive(suite.analysis.plannerVersion),
                    "reconstructionProfileSha256" to JsonPrimitive(reconstructionProfileSha256),
                ),
            ),
            "engine" to JsonObject(
                mapOf(
                    "id" to JsonPrimitive(engine.id),
                    "oracleManifestSha256" to JsonPrimitive(engine.oracleManifestSha256),
                    "inputPath" to JsonPrimitive(engine.strippedArtifact.relativePath),
                    "inputBytes" to JsonPrimitive(engine.strippedArtifact.bytes),
                    "inputSha256" to JsonPrimitive(engine.strippedArtifact.sha256),
                ),
            ),
            "budgets" to JsonObject(
                mapOf(
                    "wallClockMillis" to JsonPrimitive(suite.budgets.exportWallClockMillis),
                    "maximumResidentBytes" to JsonPrimitive(suite.budgets.exportMaximumResidentBytes),
                    "plannerMaximumEntities" to JsonPrimitive(suite.budgets.plannerMaximumEntities),
                    "plannerMaximumDependencyEdges" to JsonPrimitive(suite.budgets.plannerMaximumDependencyEdges),
                    "plannerMaximumWorkUnits" to JsonPrimitive(suite.budgets.plannerMaximumWorkUnits),
                ),
            ),
            "results" to JsonObject(
                mapOf(
                    "wallClockMillis" to JsonPrimitive(wallClockMillis),
                    "maximumResidentBytesObserved" to JsonPrimitive(maximumResidentBytesObserved),
                    "export" to JsonObject(
                        mapOf(
                            "functions" to JsonPrimitive(progress.functions),
                            "recovered" to JsonPrimitive(progress.recovered),
                            "partial" to JsonPrimitive(progress.partial),
                            "failed" to JsonPrimitive(progress.failed),
                            "reused" to JsonPrimitive(progress.reused),
                        ),
                    ),
                    "programModel" to programModel.json("analysis/reports/program_model.json"),
                    "modulePlan" to modulePlan.json("planning/module_plan.json"),
                    "ownership" to JsonObject(
                        mapOf(
                            "modules" to JsonPrimitive(moduleCount),
                            "functions" to JsonPrimitive(model.functions.size),
                            "globals" to JsonPrimitive(model.globals.size),
                            "types" to JsonPrimitive(model.types.size),
                            "functionsAssignedExactlyOnce" to JsonPrimitive(true),
                            "globalsAssignedExactlyOnce" to JsonPrimitive(true),
                            "typesAssignedExactlyOnce" to JsonPrimitive(true),
                        ),
                    ),
                ),
            ),
        )
        val unsigned = JsonObject(fields)
        val reportSha256 = OracleArtifacts.sha256(OracleJson.canonicalBytes(unsigned, evidenceJsonLimits(MAXIMUM_EVIDENCE_BYTES)))
        val document = JsonObject(fields + ("reportSha256" to JsonPrimitive(reportSha256)))
        OracleSchemas.validate("gcc/compiler-engine-plan-evidence", document)
        return OracleJson.canonicalBytes(document, evidenceJsonLimits(MAXIMUM_EVIDENCE_BYTES))
    }

    private fun prepareOutputDirectory(path: Path): Path {
        val output = path.toAbsolutePath().normalize()
        output.createDirectories()
        stableDirectory(output, "compiler-engine output directory")
        return output
    }

    private fun publishDeterministic(path: Path, bytes: ByteArray, label: String) {
        if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            val existing = digestStableArtifact(path, bytes.size.toLong(), label)
            if (existing.bytes != bytes.size.toLong() || existing.sha256 != OracleArtifacts.sha256(bytes)) {
                throw GccCompilerEnginePlanningException("resumed $label differs from deterministic output")
            }
            return
        }
        try {
            writeProjectEvidenceAtomically(path, bytes)
        } catch (failure: Exception) {
            throw GccCompilerEnginePlanningException("cannot publish $label", failure)
        }
    }

    private fun elapsedMillis(started: Long): Long = Duration.ofNanos(System.nanoTime() - started).toMillis()

    private data class ExportProgress(
        val functions: Long,
        val completed: Long,
        val recovered: Long,
        val partial: Long,
        val failed: Long,
        val reused: Long,
    )

    private companion object {
        const val MAXIMUM_PROGRESS_BYTES = 1024 * 1024
        const val MAXIMUM_EVIDENCE_BYTES = 4 * 1024 * 1024
        const val MAXIMUM_MODULE_PLAN_BYTES = 512 * 1024 * 1024
        const val MAXIMUM_PROGRAM_MODEL_BYTES = 8L * 1024 * 1024 * 1024
        val EXPORT_PROGRESS_KEYS = setOf(
            "schemaVersion",
            "phase",
            "completed",
            "total",
            "recovered",
            "partial",
            "failed",
            "reused",
            "currentFunction",
        )
        val EXPORT_RECOVERY_STATUSES = setOf(RecoveryStatus.RECOVERED, RecoveryStatus.PARTIAL, RecoveryStatus.FAILED)
    }
}

private data class StableArtifact(val path: Path, val bytes: Long, val sha256: String) {
    fun json(relativePath: String) = JsonObject(
        mapOf(
            "path" to JsonPrimitive(relativePath),
            "bytes" to JsonPrimitive(bytes),
            "sha256" to JsonPrimitive(sha256),
        ),
    )
}

private fun digestStableArtifact(path: Path, maximumBytes: Long, label: String): StableArtifact {
    val normalized = path.toAbsolutePath().normalize()
    val parent = normalized.parent ?: throw GccCompilerEnginePlanningException("$label path has no parent")
    val parentBefore = stableDirectory(parent, "$label parent")
    val before = stableFile(normalized, label)
    val permissions = trustedPermissions(normalized, label)
    if (before.size() !in 1..maximumBytes) {
        throw GccCompilerEnginePlanningException("$label exceeds its bounded artifact limit")
    }
    val digest = MessageDigest.getInstance("SHA-256")
    try {
        FileChannel.open(normalized, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS).use { channel ->
            val buffer = ByteBuffer.allocate(1024 * 1024)
            var observed = 0L
            while (observed < before.size()) {
                buffer.clear()
                buffer.limit(minOf(buffer.capacity().toLong(), before.size() - observed).toInt())
                val count = channel.read(buffer)
                if (count <= 0) throw GccCompilerEnginePlanningException("$label ended while hashing")
                digest.update(buffer.array(), 0, count)
                observed = Math.addExact(observed, count.toLong())
            }
            buffer.clear()
            buffer.limit(1)
            if (channel.read(buffer) >= 0 || channel.size() != before.size()) {
                throw GccCompilerEnginePlanningException("$label changed size while hashing")
            }
        }
    } catch (failure: GccCompilerEnginePlanningException) {
        throw failure
    } catch (failure: Exception) {
        throw GccCompilerEnginePlanningException("cannot hash $label", failure)
    }
    val after = stableFile(normalized, label)
    val parentAfter = stableDirectory(parent, "$label parent")
    if (!sameVersion(before, after) || parentBefore.fileKey() != parentAfter.fileKey() ||
        permissions != trustedPermissions(normalized, label)
    ) {
        throw GccCompilerEnginePlanningException("$label identity, metadata, parent, or permissions changed while hashing")
    }
    return StableArtifact(normalized, before.size(), digest.digest().hex())
}

private class ProcessTreeResourceMonitor(
    private val maximumResidentBytes: Long,
    maximumWallClockMillis: Long,
) : AutoCloseable {
    private val startedNanos = System.nanoTime()
    private val maximumWallClockNanos = Math.multiplyExact(maximumWallClockMillis, 1_000_000L)
    private val running = AtomicBoolean(true)
    private val maximumObserved = AtomicLong(0L)
    private val limitExceeded = AtomicBoolean(false)
    private val deadlineExceeded = AtomicBoolean(false)
    private val terminationRequested = AtomicBoolean(false)
    private val thread = Thread(::sampleUntilClosed, "gcc-engine-resource-monitor").also {
        it.isDaemon = true
        it.start()
    }

    val peakResidentBytes: Long
        get() = maximumObserved.get()
    val exceeded: Boolean
        get() = limitExceeded.get()
    val wallClockExceeded: Boolean
        get() = deadlineExceeded.get()

    private fun sampleUntilClosed() {
        while (running.get()) {
            sample()
            try {
                Thread.sleep(25)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                break
            }
        }
        sample()
    }

    private fun sample() {
        val root = ProcessHandle.current()
        val handles = root.descendants().toList() + root
        val observed = handles.distinctBy { it.pid() }.fold(0L) { total, handle ->
            val resident = runCatching {
                Files.readAllLines(Path.of("/proc/${handle.pid()}/status"))
                    .firstOrNull { it.startsWith("VmRSS:") }
                    ?.trim()?.split(Regex("\\s+"))?.getOrNull(1)?.toLong()
                    ?.let { Math.multiplyExact(it, 1024L) } ?: 0L
            }.getOrDefault(0L)
            try {
                Math.addExact(total, resident)
            } catch (_: ArithmeticException) {
                Long.MAX_VALUE
            }
        }
        maximumObserved.accumulateAndGet(observed, ::maxOf)
        val elapsedNanos = System.nanoTime() - startedNanos
        if (elapsedNanos >= maximumWallClockNanos) deadlineExceeded.set(true)
        if (observed > maximumResidentBytes) limitExceeded.set(true)
        if ((limitExceeded.get() || deadlineExceeded.get()) && terminationRequested.compareAndSet(false, true)) {
            root.descendants().toList().asReversed().forEach { handle -> if (handle.isAlive) handle.destroy() }
        }
    }

    override fun close() {
        if (!running.compareAndSet(true, false)) return
        thread.interrupt()
        thread.join(2_000)
        if (thread.isAlive) throw GccCompilerEnginePlanningException("resource monitor did not terminate")
        sample()
    }
}

private fun JsonObject.stringField(name: String): String {
    val primitive = this[name] as? JsonPrimitive
        ?: throw GccCompilerEnginePlanningException("progress field $name is not a string")
    if (!primitive.isString) throw GccCompilerEnginePlanningException("progress field $name is not a string")
    return primitive.content
}

private fun JsonObject.longField(name: String): Long {
    val primitive = this[name] as? JsonPrimitive
        ?: throw GccCompilerEnginePlanningException("progress field $name is not an integer")
    if (primitive.isString || primitive.content.any { it in ".eE" }) {
        throw GccCompilerEnginePlanningException("progress field $name is not an integer")
    }
    val value = primitive.content.toLongOrNull()
        ?: throw GccCompilerEnginePlanningException("progress field $name exceeds the Kotlin integer range")
    if (value < 0L) throw GccCompilerEnginePlanningException("progress field $name is negative")
    return value
}

private fun evidenceJsonLimits(maximumBytes: Int) = StrictJsonLimits(
    maximumInputBytes = maximumBytes,
    maximumCanonicalBytes = maximumBytes,
    maximumDepth = 64,
    maximumNodes = 100_000,
    maximumStringBytes = minOf(maximumBytes, 1024 * 1024),
    maximumTotalStringBytes = maximumBytes,
)

private fun ByteArray.hex(): String = joinToString("") { byte ->
    (byte.toInt() and 0xff).toString(16).padStart(2, '0')
}
