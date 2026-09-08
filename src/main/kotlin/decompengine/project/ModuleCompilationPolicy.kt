package decompengine.project

import java.nio.file.Path

/** Local compilation policy, selected by a registered reconstruction profile. */
internal interface ModuleCompilationPolicy {
    val id: String
    fun command(profile: ReconstructionProfile, sourcePath: String): List<String>
    fun validate(projectDir: Path, sourcePath: String, profile: ReconstructionProfile): ModuleCompilationEvidence
}

/** Registration is application-owned; profile data cannot supply executable policy code. */
internal object ReconstructionCompilationPolicies {
    fun resolve(profile: ReconstructionProfile): ModuleCompilationPolicy {
        if (GeneratedCMakeReconstructionProfile.supports(profile)) return GeneratedCModuleValidation
        throw IllegalArgumentException("no module compilation policy registered for profile: ${profile.id}")
    }
}
