package decompengine.project

import decompengine.repair.RepairResourceBudget
import decompengine.repair.RepairIndexProfile
import java.nio.file.Path

/** Content-independent source authorization shared by indexing, recovery and validation staging. */
internal class GeneratedCRepairSourcePolicy(private val profile: ReconstructionProfile) {
    val buildDefinition = profile.layout.declaration("build-definition").materialize()
    private val sourceDeclarations = profile.layout.declarations.filter {
        ProjectFileRole.BUILD_INPUT in it.roles && ProjectFileRole.BUILD_DEFINITION !in it.roles
    }
    val sourceRoots = declaredRoots(sourceDeclarations)
    val rootFiles = sourceDeclarations.mapNotNull { declaration ->
        declaration.pathTemplate.takeIf { '/' !in it }
    }.sorted()
    val interfaceRoots = declaredRoots(sourceDeclarations.filter {
        ProjectFileRole.PUBLIC_INTERFACE in it.roles || ProjectFileRole.PRIVATE_INTERFACE in it.roles
    })

    init {
        ReconstructionAdapters.resolve(profile)
        require(sourceRoots.isNotEmpty() || rootFiles.isNotEmpty()) {
            "generated-C repair profile has no declared source inputs"
        }
    }

    fun admitsSourcePath(path: String): Boolean =
        (path == buildDefinition || path in rootFiles || sourceRoots.any { path.startsWith("$it/") }) &&
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

    private fun declaredRoots(declarations: List<ProjectFileDeclaration>): List<String> {
        val roots = declarations.mapNotNull { declaration ->
            val parent = declaration.pathTemplate.substringBeforeLast('/', "")
            if (parent.isEmpty()) {
                require('{' !in declaration.pathTemplate) {
                    "generated-C repair cannot discover a root-level template input"
                }
                null
            } else {
                require('{' !in parent && '}' !in parent) {
                    "generated-C repair source root must be a static declared directory: $parent"
                }
                parent
            }
        }.distinct().sortedWith(compareBy<String> { it.length }.thenBy { it })
        return roots.filter { root -> roots.none { other -> other != root && root.startsWith("$other/") } }.sorted()
    }
}

/** One immutable index/staging policy; constructing this alone grants no execution authority. */
internal class GeneratedCValidationRegistration(val profile: ReconstructionProfile) {
    val indexProfile: RepairIndexProfile = GeneratedCRepairIndexProfile.forProfile(profile)
    val sources = GeneratedCRepairSourcePolicy(profile)

    fun requireIdentity(profileId: String, profileSha256: String, budget: RepairResourceBudget) {
        require(profileId == indexProfile.profileId() &&
            profileSha256 == indexProfile.configurationSha256(budget)) {
            "validation request differs from the registered generated-C repair profile"
        }
    }

    fun requireSourceLayout(paths: List<String>, budget: RepairResourceBudget) {
        require(sources.buildDefinition in paths &&
            sources.authorizesRecoveryLayout(paths, paths.filter(sources::isEditable), budget)) {
            "candidate source layout is not authorized by the generated-C profile"
        }
    }

    fun buildCommand(buildTool: Path, compiler: Path, shell: Path): List<String> {
        require(buildTool.fileName.toString() == profile.adapterConfiguration.getValue("build-executable").single()) {
            "validation build tool differs from the selected repair profile"
        }
        require(compiler.fileName.toString() == profile.adapterConfiguration.getValue("compiler-driver").single()) {
            "validation compiler differs from the selected repair profile"
        }
        require(shell.fileName.toString() == "sh") { "validation shell differs from the generated-C repair policy" }
        return when (profile.adapterConfiguration.getValue("build-system").single()) {
            "gnu-make" -> listOf(buildTool.toString(), "--no-builtin-rules", "--no-builtin-variables",
                "--no-print-directory", "-f", sources.buildDefinition,
                "CC=$compiler -B${GeneratedCRepairRuntimeConfiguration.TOOL_DIRECTORY}/", "SHELL=$shell",
                "TARGET=build/reconstructed", "all")
            "ninja" -> listOf(buildTool.toString(), "-f", sources.buildDefinition, "build/reconstructed")
            else -> throw IllegalArgumentException("unsupported selected repair build system")
        }
    }
}

/** Production still registers only the exact built-in Make descriptor and unavailable validator. */
internal object GeneratedCValidationProfile {
    val registeredMake = GeneratedCValidationRegistration(GeneratedCMakeReconstructionProfile.descriptor)
    val sources: GeneratedCRepairSourcePolicy get() = registeredMake.sources

    fun requireIdentity(profileId: String, profileSha256: String, budget: RepairResourceBudget) =
        registeredMake.requireIdentity(profileId, profileSha256, budget)

    fun requireSourceLayout(paths: List<String>, budget: RepairResourceBudget) =
        registeredMake.requireSourceLayout(paths, budget)
}
