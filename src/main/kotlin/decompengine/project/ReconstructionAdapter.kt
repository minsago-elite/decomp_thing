package decompengine.project

import java.nio.file.Path
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject

/** Local generation policy; production execution authority is a separate contract. */
internal interface ReconstructionAdapter {
    val diagnostics: ToolchainDiagnosticPolicy
    val compilation: ModuleCompilationPolicy
    val archiveBuild: ArchiveBuildPolicy
    val behaviorBuild: BehaviorBuildPolicy
    val mvpPatchCompiler: MvpPatchCompilerPolicy
    fun validateProfile(profile: ReconstructionProfile) = Unit
    fun evidenceOnlyProfile(profile: ReconstructionProfile): ReconstructionProfile =
        throw IllegalArgumentException("adapter does not support evidence-only reconstruction: ${profile.id}")
    fun evidenceOnlyReconstructor(profile: ReconstructionProfile): ModuleReconstructor =
        throw IllegalArgumentException("adapter does not support evidence-only reconstruction: ${profile.id}")
    fun build(
        projectDir: Path,
        profile: ReconstructionProfile,
        hostSafetyLimits: ReconstructionHostSafetyLimits = ReconstructionHostSafetyLimits.DEFAULT,
    ): BuildReport
    fun rendering(model: RecoveredProgramModel, plan: ModulePlan, profile: ReconstructionProfile): ProjectRendering
    fun admitGeneration(projectDir: Path, profile: ReconstructionProfile, reconstructor: ModuleReconstructor) = Unit
    fun requiresUnresolvedOutput(profile: ReconstructionProfile): Boolean = false
    fun diagnosticPurposeDescription(profile: ReconstructionProfile): String = "diagnostic-only output"
    fun requireImplementationPurpose(profile: ReconstructionProfile, operation: String) {
        require(!requiresUnresolvedOutput(profile)) { "diagnostic-only output cannot authorize $operation" }
    }
    fun validateSourceContent(profile: ReconstructionProfile, bytes: ByteArray, label: String) = Unit
    fun verifyArchivePurpose(projectDir: Path, profile: ReconstructionProfile, manifest: SourceTreeManifest,
        payloadPaths: Set<String>) = Unit
    fun validateArchivedCheckpoint(profile: ReconstructionProfile, source: GeneratedFileEvidence,
        checkpoint: ArchivedModuleCheckpointProvenance) = Unit
    fun modulePrompt(request: ModuleReconstructionRequest): ModulePromptContent
    fun defaultReconstructor(): ModuleReconstructor
    fun assess(module: PlannedModule, model: RecoveredProgramModel, generator: String, source: String): List<ModuleReconstructionIssue>
    fun assess(module: PlannedModule, model: RecoveredProgramModel, generator: String, source: String, profile: ReconstructionProfile): List<ModuleReconstructionIssue> = assess(module, model, generator, source)
    fun toolchainEvidence(profile: ReconstructionProfile): String
}

/** Parsed archive facts only; the selected adapter determines what authority they can establish. */
internal data class ArchivedModuleCheckpointProvenance(
    val schemaVersion: Long,
    val generator: String,
    val reconstructorIdentity: String,
    val accepted: Boolean,
    val compilationPresent: Boolean,
    val executionEvidencePresent: Boolean,
    val repairLineagePresent: Boolean,
)

internal data class ModulePromptContent(val objective: String, val evidence: String)

internal interface ProjectRendering {
    fun sharedInterface(): String
    fun moduleInterface(module: PlannedModule): String
    fun privateInterface(module: PlannedModule): String
    fun entrypoint(): RenderedEntrypoint?
    fun buildDefinition(sources: List<String>, profile: ReconstructionProfile): String
}

internal data class RenderedEntrypoint(val source: String, val entityIds: List<String>)

/** Application-owned dispatch; profile data cannot register executable implementations. */
internal object ReconstructionAdapters {
    fun resolve(profile: ReconstructionProfile): ReconstructionAdapter {
        val adapter = when (profile.id) {
        GeneratedCMakeReconstructionProfile.PROFILE_ID -> GeneratedCReconstructionAdapter
        GeneratedCNinjaReconstructionProfile.PROFILE_ID -> GeneratedCNinjaReconstructionAdapter
        else -> throw IllegalArgumentException("no reconstruction adapter registered for profile: ${profile.id}")
        }
        adapter.validateProfile(profile)
        return adapter
    }
}

/** Build-system-specific evidence requirements inside the shared archive transport. */
internal interface ArchiveBuildPolicy {
    fun requiredPaths(profile: ReconstructionProfile): Set<String>
    fun transportLayout(profile: ReconstructionProfile): ArchiveTransportLayout
    val rebuildInstructions: String
    fun validate(projectDir: Path, profile: ReconstructionProfile, requireArtifact: Boolean)
    fun sourceRevision(projectDir: Path, profile: ReconstructionProfile): BuildSourceRevision
    fun isBuildInput(profile: ReconstructionProfile, relativePath: String): Boolean
}

/** Validate application-owned transport policy before preparing archive paths. */
internal fun ArchiveBuildPolicy.checkedTransportLayout(profile: ReconstructionProfile): ArchiveTransportLayout =
    transportLayout(profile).also { layout ->
        val required = requiredPaths(profile)
        require(required.containsAll(layout.strictBuildControlPaths)) {
            "archive build controls must be required payload evidence"
        }
        layout.requireRetains(required + setOf("ARCHIVE_MANIFEST.sha256", "ARCHIVE_README.md", "source_tree_manifest.json",
            profile.layout.declaration("program-model-evidence").materialize()))
        layout.requireRetainsDeclarations(profile.layout.declarations.filter { ProjectFileRole.ARCHIVE_PAYLOAD in it.roles })
    }

/** Application-owned build evidence policy; capture retains its own read and inventory bounds. */
internal interface BehaviorBuildPolicy {
    fun layout(profile: ReconstructionProfile): BehaviorBuildLayout
    fun parseContract(contract: JsonObject, profile: ReconstructionProfile): BehaviorBuildContract
}

internal data class BehaviorBuildLayout(
    val contractPath: String,
    val artifactPath: String,
    val standaloneInputs: List<String>,
    val sourceRoots: List<String>,
)

internal data class BehaviorBuildContract(
    val sourceRevisionSha256: String,
    val sourceInputs: JsonArray,
    val artifact: JsonObject,
)
