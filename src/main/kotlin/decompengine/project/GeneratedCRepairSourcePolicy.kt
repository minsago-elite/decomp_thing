package decompengine.project

import decompengine.repair.RepairResourceBudget

/** Content-independent source authorization shared by indexing, recovery and validation staging. */
internal class GeneratedCRepairSourcePolicy(private val profile: ReconstructionProfile) {
    val buildDefinition = profile.layout.declaration("build-definition").materialize()

    init {
        ReconstructionAdapters.resolve(profile)
        require(profile.layout.declarations.filter { ProjectFileRole.BUILD_INPUT in it.roles }.all {
            it.pathTemplate == buildDefinition || it.pathTemplate.startsWith("src/") || it.pathTemplate.startsWith("include/")
        }) { "generated-C repair build inputs must use the supported source roots" }
    }

    fun admitsSourcePath(path: String): Boolean =
        (path == buildDefinition || path.startsWith("src/") || path.startsWith("include/")) &&
            path.split('/').none { it.endsWith(".repair") }

    fun isEditable(path: String): Boolean {
        val declarations = profile.layout.declarations.filter { it.matches(path) }
        require(declarations.size <= 1) { "repair path has ambiguous profile declarations: $path" }
        val declaration = declarations.singleOrNull() ?: return false
        return ProjectFileRole.BUILD_INPUT in declaration.roles &&
            ProjectFileRole.EDITABLE in declaration.roles && declaration.contentKind == ProjectContentKind.UTF8_TEXT
    }

    fun authorizesRecoveryLayout(paths: List<String>, editable: List<String>, budget: RepairResourceBudget): Boolean {
        if (paths.isEmpty() || paths.size > budget.maximumSourceFiles) return false
        if (paths != paths.distinct().sorted() || editable != editable.distinct().sorted()) return false
        if (paths.any { !admitsSourcePath(it) }) return false
        return editable == paths.filter(::isEditable)
    }
}

/** The production validator still registers exactly the built-in Make descriptor. */
internal object GeneratedCValidationProfile {
    val sources = GeneratedCRepairSourcePolicy(GeneratedCMakeReconstructionProfile.descriptor)

    fun requireIdentity(profileId: String, profileSha256: String, budget: RepairResourceBudget) {
        require(profileId == GeneratedCRepairIndexProfile.profileId() &&
            profileSha256 == GeneratedCRepairIndexProfile.configurationSha256(budget)) {
            "validation request differs from the registered generated-C repair profile"
        }
    }

    fun requireSourceLayout(paths: List<String>, budget: RepairResourceBudget) {
        require(sources.buildDefinition in paths &&
            sources.authorizesRecoveryLayout(paths, paths.filter(sources::isEditable), budget)) {
            "candidate source layout is not authorized by the generated-C profile"
        }
    }
}
