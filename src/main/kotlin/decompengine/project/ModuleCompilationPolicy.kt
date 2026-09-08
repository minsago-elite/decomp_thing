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
        val registered = GeneratedCMakeReconstructionProfile.descriptor
        val benchmarkMetadata = setOf(
            "benchmark-profile-id", "benchmark-profile-sha256", "benchmark-target", "benchmark-version",
        )
        fun declarationShape(candidate: ReconstructionProfile) = candidate.layout.declarations.map { declaration ->
            Triple(declaration.id, declaration.roles, declaration.contentKind)
        }
        if (profile.schemaVersion == registered.schemaVersion &&
            declarationShape(profile) == declarationShape(registered) &&
            registered.adapterConfiguration.keys.all { it in profile.adapterConfiguration.keys } &&
            profile.adapterConfiguration.keys.all { it in registered.adapterConfiguration.keys || it in benchmarkMetadata } &&
            profile.adapterConfiguration["compiler-driver"]?.size == 1 &&
            profile.adapterConfiguration["compiler-flags"] != null
        ) return GeneratedCModuleValidation
        throw IllegalArgumentException("no module compilation policy registered for profile: ${profile.id}")
    }
}
