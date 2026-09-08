package decompengine.project

import java.util.Collections

/** Built-in descriptors admitted by user-facing profile selection and evidence readers. */
object ReconstructionProfiles {
    val builtIn: List<ReconstructionProfile> = Collections.unmodifiableList(listOf(
        GeneratedCMakeReconstructionProfile.descriptor,
        GeneratedCNinjaReconstructionProfile.descriptor,
    ))
    fun named(id: String): ReconstructionProfile = builtIn.singleOrNull { it.id == id }
        ?: throw IllegalArgumentException("unsupported reconstruction profile: $id")
}
