package decompengine.oracle.gcc

import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.permissions
import decompengine.analysis.AnalysisDeadline
import decompengine.oracle.core.DescriptorBoundAtomicStateFile
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.fulltree.StableControlFile
import decompengine.project.ArchivalReconstructionResult
import decompengine.project.ArchivalReconstructionService
import decompengine.project.AssessedProgramModelAnalyzer
import decompengine.project.GeneratedCMakeReconstructionProfile
import decompengine.project.ProgramAnalysisResult
import decompengine.project.ReconstructionAdapters
import decompengine.project.ReconstructionProfile
import decompengine.project.ReconstructionProfiles
import java.nio.file.Files
import java.nio.file.Path
import java.util.Collections
import java.util.concurrent.TimeUnit
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Closed, evidence-only selection. Model generation and accepted implementation stay separate. */
internal class GccStructuralReconstructionOptions private constructor(
    val output: Path,
    val analysisOptions: GccBundledCliOptions,
    analysisArguments: List<String>,
    val reconstructionProfile: ReconstructionProfile,
) {
    val analysisArguments: List<String> = Collections.unmodifiableList(ArrayList(analysisArguments))
    val reconstructionOutput: Path = output.resolve("reconstruction")

    companion object {
        fun parse(arguments: List<String>): GccStructuralReconstructionOptions {
            require(arguments.size in 1..30 && arguments.sumOf { it.toByteArray().size.toLong() + 1 } <= 65536) {
                "structural reconstruction arguments exceed their bound"
            }
            val analysis = mutableListOf("driver")
            var selectedProfile: String? = null
            var index = 0
            while (index < arguments.size) {
                val argument = arguments[index++]
                if (argument == "--reconstruction-profile") {
                    require(selectedProfile == null && index < arguments.size) { "duplicate or incomplete reconstruction profile" }
                    selectedProfile = arguments[index++]
                } else analysis += argument
            }
            val outer = GccBundledCliOptions.parse(analysis, fullRecoveryExport = true)
            require(outer.engineId == "driver")
            val profile = ReconstructionProfiles.named(selectedProfile ?: GeneratedCMakeReconstructionProfile.PROFILE_ID)
            val evidenceOnly = ReconstructionAdapters.resolve(profile).evidenceOnlyProfile(profile)
            val outputIndex = analysis.indexOf("--output")
            check(outputIndex >= 0)
            analysis[outputIndex + 1] = outer.output.resolve("analysis").toString()
            val inner = GccBundledCliOptions.parse(analysis, fullRecoveryExport = true)
            return GccStructuralReconstructionOptions(outer.output, inner, analysis, evidenceOnly)
        }
    }
}

/** Immutable current invocation selection, not an oracle or execution admission. */
internal class GccStructuralReconstructionInvocation private constructor(
    val options: GccStructuralReconstructionOptions,
    bytes: ByteArray,
    identities: Map<Path, LinuxFileIdentity>,
    private val control: StableControlFile,
) : AutoCloseable {
    private val encoded = bytes.copyOf()
    private val directories = java.util.Map.copyOf(identities)
    private var closed = false
    val canonicalBytes: ByteArray get() = encoded.copyOf()

    fun requireAnalysisSelection(selected: GccBundledCliOptions, arguments: List<String>) {
        requireCurrent()
        require(selected == options.analysisOptions && arguments == options.analysisArguments) {
            "structural reconstruction analysis selection changed"
        }
    }

    fun requireCurrent() {
        check(!closed) { "structural reconstruction invocation is closed" }
        if (Thread.currentThread().isInterrupted) throw InterruptedException("structural reconstruction cancelled")
        directories.forEach { (path, expected) ->
            require(path.toRealPath() == path) { "structural reconstruction directory became an alias" }
            LinuxFilesystemSyscalls.openRoot(path).use { current ->
                require(current.identity.copy(linkCount = expected.linkCount) == expected) {
                    "structural reconstruction directory identity changed"
                }
            }
        }
        control.verifyUnchanged("structural reconstruction invocation")
    }

    override fun close() {
        if (!closed) {
            closed = true
            control.close()
        }
    }

    companion object {
        fun create(options: GccStructuralReconstructionOptions, arguments: List<String>): GccStructuralReconstructionInvocation {
            val reparsed = GccStructuralReconstructionOptions.parse(arguments)
            require(reparsed.output == options.output && reparsed.analysisOptions == options.analysisOptions &&
                reparsed.analysisArguments == options.analysisArguments &&
                reparsed.reconstructionProfile.sha256 == options.reconstructionProfile.sha256) {
                "structural reconstruction argv differs from its selection"
            }
            require(options.output.toRealPath() == options.output) { "structural reconstruction output must not contain aliases" }
            val uid = (Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toInt()
            require(uid > 0) { "structural reconstruction requires an ordinary controller UID" }
            val identities = linkedMapOf<Path, LinuxFileIdentity>()
            val bytes = LinuxFilesystemSyscalls.openRoot(options.output).use { root ->
                require(root.identity.uid == uid && root.identity.mode.permissions == 448 &&
                    LinuxFilesystemSyscalls.directoryEntryNames(root, 1).isEmpty()) {
                    "structural reconstruction output must be an empty private directory owned by the controller"
                }
                identities[options.output] = root.identity
                for (name in listOf("analysis", "reconstruction")) {
                    LinuxFilesystemSyscalls.createDirectory(root.fd, name, 448)
                    LinuxFilesystemSyscalls.openDirectoryAt(root.fd, name).use { child ->
                        LinuxFilesystemSyscalls.chmod(child, 448)
                        LinuxFilesystemSyscalls.synchronize(child)
                        identities[options.output.resolve(name)] = child.identity
                    }
                }
                val selection = JsonObject(mapOf(
                    "provider" to JsonPrimitive("owned-selected-assessment-reconstruction-invocation-v1"),
                    "schemaVersion" to JsonPrimitive(1), "mode" to JsonPrimitive("evidence-only"),
                    "argv" to JsonArray((listOf("gcc-driver-reconstruct") + arguments).map(::JsonPrimitive)),
                    "analysisArgv" to JsonArray((listOf("gcc-engine-full-export") + options.analysisArguments).map(::JsonPrimitive)),
                    "output" to JsonPrimitive(options.output.toString()),
                    "analysisOutput" to JsonPrimitive(options.analysisOptions.output.toString()),
                    "reconstructionOutput" to JsonPrimitive(options.reconstructionOutput.toString()),
                    "reconstructionProfileId" to JsonPrimitive(options.reconstructionProfile.id),
                    "reconstructionProfileSha256" to JsonPrimitive(options.reconstructionProfile.sha256),
                    "directories" to JsonArray(identities.map { (path, identity) -> JsonObject(mapOf(
                        "path" to JsonPrimitive(path.toString()), "device" to JsonPrimitive(identity.key.device),
                        "inode" to JsonPrimitive(identity.key.inode), "mountId" to JsonPrimitive(identity.mountId),
                        "uid" to JsonPrimitive(identity.uid), "gid" to JsonPrimitive(identity.gid), "mode" to JsonPrimitive(identity.mode))) }),
                ))
                OracleJson.canonicalBytes(selection).also {
                    DescriptorBoundAtomicStateFile.publishNoReplace(root, "reconstruction-invocation.json", it, 256 * 1024)
                    LinuxFilesystemSyscalls.synchronize(root)
                }
            }
            val control = StableControlFile.open(options.output.resolve("reconstruction-invocation.json"),
                256L * 1024, "structural reconstruction invocation")
            try {
                require(control.authenticatedSha256 == OracleArtifacts.sha256(bytes)) { "structural reconstruction invocation changed during publication" }
                return GccStructuralReconstructionInvocation(options, bytes, identities, control).also { it.requireCurrent() }
            } catch (failure: Throwable) {
                try { control.close() } catch (cleanup: Throwable) { failure.addSuppressed(cleanup) }
                throw failure
            }
        }
    }
}

/** Fixed application-owned analysis; neither serialized reports nor an injected producer can substitute for execution. */
internal class GccOwnedStructuralProgramModelAnalyzer(
    private val invocation: GccStructuralReconstructionInvocation,
) : AssessedProgramModelAnalyzer {
    private var used = false

    @Synchronized
    override fun analyzeWithAssessment(binaryPath: Path, workDir: Path): ProgramAnalysisResult {
        check(!used) { "owned structural analysis may be consumed once" }
        val options = invocation.options
        require(binaryPath.toAbsolutePath().normalize() == options.analysisOptions.binary &&
            workDir.toAbsolutePath().normalize() == options.reconstructionOutput.resolve("analysis")) {
            "owned structural analysis caller differs from its bound invocation"
        }
        used = true
        invocation.requireCurrent()
        val publication = GccBundledCliCommand.runDriverAnalysis(options.analysisOptions, options.analysisArguments, invocation)
        requireNotNull(publication.selectedInputs) { "owned driver analysis did not admit selected structural evidence" }
        // This is a bounded report-snapshot phase after execution, not a renewed execution lease.
        // Both full invocation validations consume this same allowance.
        val deadline = AnalysisDeadline.start(TimeUnit.MILLISECONDS.toNanos(options.reconstructionProfile.budgets.exportWallClockMillis),
            "owned structural reconstruction snapshot")
        return snapshotStructuralAnalysis(publication, deadline, invocation::requireCurrent)
    }
}

/**
 * Composes the existing passive model transport; this does not execute a producer or issue admission.
 * The owned caller fixes [requireInvocationCurrent] to its retained invocation. Component controls
 * can observe model checkpoints without replacing the deadline or the final validation.
 */
internal fun snapshotStructuralAnalysis(
    publication: GccBundledFullExportPublication,
    deadline: AnalysisDeadline,
    requireInvocationCurrent: () -> Unit,
    modelCheckpoint: (String) -> Unit = {},
): ProgramAnalysisResult {
    deadline.checkpoint("before owned snapshot invocation validation")
    requireInvocationCurrent()
    deadline.checkpoint("after owned snapshot invocation validation")
    // These are defensive in-memory bytes. Per-token checks must not reopen invocation paths.
    val snapshot = ProgramAnalysisResult(publication.canonicalProgramModelBytes, publication.selectedInputs) { stage ->
        deadline.checkpoint(stage)
        modelCheckpoint(stage)
        deadline.checkpoint(stage)
    }
    requireInvocationCurrent()
    // No observer runs after final validation, and its work is charged before the result escapes.
    deadline.checkpoint("after owned snapshot final invocation validation")
    return snapshot
}

internal object GccStructuralReconstructionCli {
    fun run(options: GccStructuralReconstructionOptions, arguments: List<String>): ArchivalReconstructionResult =
        GccStructuralReconstructionInvocation.create(options, arguments).use { invocation ->
            val adapter = ReconstructionAdapters.resolve(options.reconstructionProfile)
            val result = ArchivalReconstructionService(GccOwnedStructuralProgramModelAnalyzer(invocation),
                adapter.evidenceOnlyReconstructor(options.reconstructionProfile), profile = options.reconstructionProfile)
                .reconstruct(options.analysisOptions.binary, options.reconstructionOutput)
            invocation.requireCurrent()
            result
        }
}
