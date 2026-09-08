package decompengine.project

import java.nio.file.Path

/** Local generation policy; production execution authority is a separate contract. */
internal interface ReconstructionAdapter {
    val compilation: ModuleCompilationPolicy
    val archiveBuild: ArchiveBuildPolicy
    fun build(projectDir: Path, profile: ReconstructionProfile): BuildReport
    fun rendering(model: RecoveredProgramModel, plan: ModulePlan): ProjectRendering
    fun defaultReconstructor(): ModuleReconstructor
    fun assess(module: PlannedModule, model: RecoveredProgramModel, generator: String, source: String): List<ModuleReconstructionIssue>
    fun toolchainEvidence(profile: ReconstructionProfile): String
}

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
    fun resolve(profile: ReconstructionProfile): ReconstructionAdapter = when {
        GeneratedCMakeReconstructionProfile.supports(profile) -> GeneratedCReconstructionAdapter
        profile.id == GeneratedCNinjaReconstructionProfile.PROFILE_ID -> GeneratedCNinjaReconstructionAdapter
        else -> throw IllegalArgumentException("no reconstruction adapter registered for profile: ${profile.id}")
    }
}

/** Build-system-specific evidence requirements inside the shared archive transport. */
internal interface ArchiveBuildPolicy {
    fun requiredPaths(profile: ReconstructionProfile): Set<String>
    val rebuildInstructions: String
    fun validate(projectDir: Path, profile: ReconstructionProfile, requireArtifact: Boolean)
    fun sourceRevision(projectDir: Path, profile: ReconstructionProfile): BuildSourceRevision
    fun isBuildInput(profile: ReconstructionProfile, relativePath: String): Boolean
}
