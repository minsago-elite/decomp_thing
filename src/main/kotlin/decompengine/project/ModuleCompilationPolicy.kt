package decompengine.project

import java.nio.file.Path

/** Compiler policy is selected by a registered profile; recorded legacy commands remain explicit. */
internal interface ModuleCompilationPolicy {
    val id: String
    val legacyFingerprintIdentity: String get() = id
    fun requireAvailable(profile: ReconstructionProfile) = Unit
    fun historicalCommand(profile: ReconstructionProfile, sourcePath: String): List<String> = command(profile, sourcePath)
    fun fingerprintIdentity(checkpointVersion: Int): String = if (checkpointVersion <= 6) legacyFingerprintIdentity else id
    fun commandForCheckpoint(profile: ReconstructionProfile, sourcePath: String, checkpointVersion: Int): List<String> =
        if (checkpointVersion <= 6) historicalCommand(profile, sourcePath) else command(profile, sourcePath)
    fun command(profile: ReconstructionProfile, sourcePath: String): List<String>
    fun validate(projectDir: Path, sourcePath: String, profile: ReconstructionProfile): ModuleCompilationEvidence
}

/** Registration is application-owned; profile data cannot supply executable policy code. */
internal object ReconstructionCompilationPolicies {
    fun resolve(profile: ReconstructionProfile): ModuleCompilationPolicy =
        ReconstructionAdapters.resolve(profile).compilation
}
