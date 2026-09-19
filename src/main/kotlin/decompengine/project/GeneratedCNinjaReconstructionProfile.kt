package decompengine.project

/** Reusable generated-C profile assembled by Ninja, without a Makefile or Make invocation. */
object GeneratedCNinjaReconstructionProfile {
    const val PROFILE_ID = "generated-c-ninja-v1"
    private val base = GeneratedCMakeReconstructionProfile.descriptor
    val descriptor = ReconstructionProfile(
        base.schemaVersion, PROFILE_ID,
        ProjectLayoutProfile(base.layout.schemaVersion, base.layout.declarations.map { declaration ->
            ProjectFileDeclaration(declaration.id,
                if (declaration.id == "build-definition") "build.ninja" else declaration.pathTemplate,
                declaration.roles, declaration.contentKind)
        }),
        base.budgets,
        base.adapterConfiguration + mapOf("build-system" to listOf("ninja"), "build-executable" to listOf("ninja")),
    )
}
