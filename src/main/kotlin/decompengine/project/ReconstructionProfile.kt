package decompengine.project

import java.util.Collections
import java.util.EnumSet
import java.util.TreeMap

/** Stable, program-neutral purposes attached to an exact project file declaration. */
enum class ProjectFileRole(val wireName: String) {
    MODULE_IMPLEMENTATION("module-implementation"),
    ENTRYPOINT_IMPLEMENTATION("entrypoint-implementation"),
    PUBLIC_INTERFACE("public-interface"),
    PRIVATE_INTERFACE("private-interface"),
    BUILD_DEFINITION("build-definition"),
    BUILD_INPUT("build-input"),
    BUILD_ARTIFACT("build-artifact"),
    EVIDENCE("evidence"),
    BEHAVIOR_EVIDENCE("behavior-evidence"),
    EDITABLE("editable"),
    VIEWABLE("viewable"),
    ARCHIVE_PAYLOAD("archive-payload"),
    ;

    companion object {
        private val byWireName = entries.associateBy(ProjectFileRole::wireName)

        fun fromWireName(value: String): ProjectFileRole =
            byWireName[value] ?: throw IllegalArgumentException("unknown project file role: $value")
    }
}

/** Content interpretation is declared explicitly instead of being inferred from a filename. */
enum class ProjectContentKind(val wireName: String) {
    UTF8_TEXT("utf8-text"),
    BINARY("binary"),
    ;

    companion object {
        private val byWireName = entries.associateBy(ProjectContentKind::wireName)

        fun fromWireName(value: String): ProjectContentKind =
            byWireName[value] ?: throw IllegalArgumentException("unknown project content kind: $value")
    }
}

/**
 * One immutable layout declaration. Templates may contain named placeholders such as `{module}`;
 * each placeholder resolves to one safe path-segment value.
 */
class ProjectFileDeclaration(
    val id: String,
    val pathTemplate: String,
    roles: Set<ProjectFileRole>,
    val contentKind: ProjectContentKind,
) {
    val roles: Set<ProjectFileRole>
    private val placeholderNames: Set<String>
    private val pathMatcher: Regex

    init {
        require(id.matches(PROFILE_COMPONENT)) { "invalid project file declaration ID: $id" }
        require(roles.isNotEmpty()) { "project file declaration must have at least one role: $id" }
        require(ProjectFileRole.EDITABLE !in roles || contentKind == ProjectContentKind.UTF8_TEXT) {
            "editable project files must declare UTF-8 text content: $id"
        }
        val placeholders = PATH_PLACEHOLDER.findAll(pathTemplate).toList()
        val scrubbed = PATH_PLACEHOLDER.replace(pathTemplate, "placeholder")
        require('{' !in scrubbed && '}' !in scrubbed) { "invalid project path template: $pathTemplate" }
        requireNormalizedProjectPath(scrubbed, "project path template")
        val names = placeholders.map { it.groupValues[1] }
        require(names.distinct().size == names.size) { "project path template repeats a placeholder: $pathTemplate" }
        placeholderNames = Collections.unmodifiableSet(names.toSortedSet())
        this.roles = Collections.unmodifiableSet(
            if (roles.isEmpty()) EnumSet.noneOf(ProjectFileRole::class.java) else EnumSet.copyOf(roles),
        )
        pathMatcher = compileTemplateMatcher(pathTemplate)
    }

    fun materialize(parameters: Map<String, String> = emptyMap()): String {
        require(parameters.keys == placeholderNames) {
            "project path template $id requires parameters ${placeholderNames.sorted()}"
        }
        val materialized = PATH_PLACEHOLDER.replace(pathTemplate) { match ->
            val name = match.groupValues[1]
            val value = parameters.getValue(name)
            require(value.matches(PATH_PARAMETER)) { "invalid project path parameter $name" }
            value
        }
        return requireNormalizedProjectPath(materialized, "project path")
    }

    internal fun matches(path: String): Boolean = pathMatcher.matches(path)

    internal fun canonicalJson(): String = buildString {
        append('{')
        append("\"id\":").append(id.canonicalJsonString()).append(',')
        append("\"pathTemplate\":").append(pathTemplate.canonicalJsonString()).append(',')
        append("\"contentKind\":").append(contentKind.wireName.canonicalJsonString()).append(',')
        append("\"roles\":[")
        append(roles.map(ProjectFileRole::wireName).sorted().joinToString(",") { it.canonicalJsonString() })
        append("]}")
    }

    override fun equals(other: Any?): Boolean = other is ProjectFileDeclaration &&
        id == other.id && pathTemplate == other.pathTemplate && roles == other.roles && contentKind == other.contentKind

    override fun hashCode(): Int = arrayOf(id, pathTemplate, roles, contentKind).contentHashCode()

    override fun toString(): String = "ProjectFileDeclaration(id=$id, pathTemplate=$pathTemplate, roles=$roles, contentKind=$contentKind)"
}

/** Immutable, versioned mapping from logical file declarations to exact paths and roles. */
class ProjectLayoutProfile(
    val schemaVersion: Int,
    declarations: List<ProjectFileDeclaration>,
) {
    val declarations: List<ProjectFileDeclaration>
    private val declarationsById: Map<String, ProjectFileDeclaration>

    init {
        require(schemaVersion == CURRENT_SCHEMA_VERSION) {
            "unsupported project layout profile schemaVersion: $schemaVersion"
        }
        require(declarations.isNotEmpty()) { "project layout profile must declare files" }
        val sorted = declarations.toList().sortedBy(ProjectFileDeclaration::id)
        require(sorted.map(ProjectFileDeclaration::id).distinct().size == sorted.size) {
            "project layout file declaration IDs must be unique"
        }
        require(sorted.map(ProjectFileDeclaration::pathTemplate).distinct().size == sorted.size) {
            "project layout path templates must be unique"
        }
        this.declarations = Collections.unmodifiableList(sorted)
        declarationsById = Collections.unmodifiableMap(sorted.associateByTo(TreeMap(), ProjectFileDeclaration::id))
    }

    fun declaration(id: String): ProjectFileDeclaration =
        declarationsById[id] ?: throw IllegalArgumentException("unknown project file declaration: $id")

    fun declarationForPath(path: String): ProjectFileDeclaration {
        val normalized = requireNormalizedProjectPath(path, "project path")
        val matching = declarations.filter { it.matches(normalized) }
        require(matching.size == 1) {
            if (matching.isEmpty()) "project path is not declared by the layout profile: $normalized"
            else "project path matches multiple layout declarations: $normalized"
        }
        return matching.single()
    }

    internal fun canonicalJson(): String = buildString {
        append("{\"schemaVersion\":").append(schemaVersion).append(",\"files\":[")
        append(declarations.joinToString(",", transform = ProjectFileDeclaration::canonicalJson))
        append("]}")
    }

    companion object {
        const val CURRENT_SCHEMA_VERSION = 1
    }
}

/** Requested limits are profile inputs and are distinct from host-owned safety ceilings. */
data class ReconstructionBudgets(
    val exportWallClockMillis: Long,
    val exportMaximumResidentBytes: Long,
    val plannerMaximumEntities: Int,
    val plannerMaximumDependencyEdges: Long,
    val plannerMaximumWorkUnits: Long,
    val maximumFunctionsPerModule: Int,
    val reconstructionMaximumContextCharacters: Int,
    val buildWallClockMillis: Long,
    val buildMaximumOutputBytes: Long,
    val archiveMaximumEntries: Int,
    val archiveMaximumFileBytes: Long,
    val archiveMaximumTotalBytes: Long,
) {
    init {
        require(exportWallClockMillis > 0) { "export wall-clock budget must be positive" }
        require(exportMaximumResidentBytes > 0) { "export resident-memory budget must be positive" }
        require(plannerMaximumEntities > 0) { "planner entity budget must be positive" }
        require(plannerMaximumDependencyEdges > 0) { "planner dependency budget must be positive" }
        require(plannerMaximumWorkUnits > 0) { "planner work budget must be positive" }
        require(maximumFunctionsPerModule > 0) { "module size budget must be positive" }
        require(reconstructionMaximumContextCharacters > 0) { "reconstruction context budget must be positive" }
        require(buildWallClockMillis > 0) { "build wall-clock budget must be positive" }
        require(buildMaximumOutputBytes > 0) { "build output budget must be positive" }
        require(archiveMaximumEntries > 0) { "archive entry budget must be positive" }
        require(archiveMaximumFileBytes > 0) { "archive file budget must be positive" }
        require(archiveMaximumTotalBytes >= archiveMaximumFileBytes) {
            "archive total budget must be at least the per-file budget"
        }
    }

    internal fun canonicalJson(): String = buildString {
        append('{')
        append("\"archiveMaximumEntries\":").append(archiveMaximumEntries).append(',')
        append("\"archiveMaximumFileBytes\":").append(archiveMaximumFileBytes).append(',')
        append("\"archiveMaximumTotalBytes\":").append(archiveMaximumTotalBytes).append(',')
        append("\"buildMaximumOutputBytes\":").append(buildMaximumOutputBytes).append(',')
        append("\"buildWallClockMillis\":").append(buildWallClockMillis).append(',')
        append("\"exportMaximumResidentBytes\":").append(exportMaximumResidentBytes).append(',')
        append("\"exportWallClockMillis\":").append(exportWallClockMillis).append(',')
        append("\"maximumFunctionsPerModule\":").append(maximumFunctionsPerModule).append(',')
        append("\"plannerMaximumDependencyEdges\":").append(plannerMaximumDependencyEdges).append(',')
        append("\"plannerMaximumEntities\":").append(plannerMaximumEntities).append(',')
        append("\"plannerMaximumWorkUnits\":").append(plannerMaximumWorkUnits).append(',')
        append("\"reconstructionMaximumContextCharacters\":").append(reconstructionMaximumContextCharacters)
        append('}')
    }
}

/** Host policy authorizes a requested profile without changing the profile's recorded identity. */
class ReconstructionHostSafetyLimits(val maximum: ReconstructionBudgets) {
    fun requireAllows(requested: ReconstructionBudgets) {
        require(requested.exportWallClockMillis <= maximum.exportWallClockMillis) {
            "requested export wall-clock budget exceeds the host safety limit"
        }
        require(requested.exportMaximumResidentBytes <= maximum.exportMaximumResidentBytes) {
            "requested export resident-memory budget exceeds the host safety limit"
        }
        require(requested.plannerMaximumEntities <= maximum.plannerMaximumEntities) {
            "requested planner entity budget exceeds the host safety limit"
        }
        require(requested.plannerMaximumDependencyEdges <= maximum.plannerMaximumDependencyEdges) {
            "requested planner dependency budget exceeds the host safety limit"
        }
        require(requested.plannerMaximumWorkUnits <= maximum.plannerMaximumWorkUnits) {
            "requested planner work budget exceeds the host safety limit"
        }
        require(requested.maximumFunctionsPerModule <= maximum.maximumFunctionsPerModule) {
            "requested module size budget exceeds the host safety limit"
        }
        require(requested.reconstructionMaximumContextCharacters <= maximum.reconstructionMaximumContextCharacters) {
            "requested reconstruction context budget exceeds the host safety limit"
        }
        require(requested.buildWallClockMillis <= maximum.buildWallClockMillis) {
            "requested build wall-clock budget exceeds the host safety limit"
        }
        require(requested.buildMaximumOutputBytes <= maximum.buildMaximumOutputBytes) {
            "requested build output budget exceeds the host safety limit"
        }
        require(requested.archiveMaximumEntries <= maximum.archiveMaximumEntries) {
            "requested archive entry budget exceeds the host safety limit"
        }
        require(requested.archiveMaximumFileBytes <= maximum.archiveMaximumFileBytes) {
            "requested archive file budget exceeds the host safety limit"
        }
        require(requested.archiveMaximumTotalBytes <= maximum.archiveMaximumTotalBytes) {
            "requested archive total budget exceeds the host safety limit"
        }
    }
}

/** Immutable, versioned reconstruction policy with a canonical project-independent identity. */
class ReconstructionProfile(
    val schemaVersion: Int,
    val id: String,
    val layout: ProjectLayoutProfile,
    val budgets: ReconstructionBudgets,
    adapterConfiguration: Map<String, List<String>> = emptyMap(),
) {
    val adapterConfiguration: Map<String, List<String>>
    val sha256: String

    init {
        require(schemaVersion == CURRENT_SCHEMA_VERSION) {
            "unsupported reconstruction profile schemaVersion: $schemaVersion"
        }
        require(id.matches(PROFILE_ID)) { "invalid reconstruction profile ID: $id" }
        val copiedConfiguration = TreeMap<String, List<String>>()
        adapterConfiguration.forEach { (key, sourceValues) ->
            require(key.matches(CONFIGURATION_KEY)) { "invalid reconstruction adapter configuration key: $key" }
            val values = sourceValues.toList()
            require(values.isNotEmpty()) { "reconstruction adapter configuration values must not be empty: $key" }
            require(values.all { it.isNotBlank() && it.length <= 4_096 && '\n' !in it && '\r' !in it }) {
                "invalid reconstruction adapter configuration value: $key"
            }
            copiedConfiguration[key] = Collections.unmodifiableList(values)
        }
        this.adapterConfiguration = Collections.unmodifiableMap(copiedConfiguration)
        sha256 = sha256(canonicalJson().toByteArray(Charsets.UTF_8))
    }

    fun canonicalJson(): String = buildString {
        append('{')
        append("\"schemaVersion\":").append(schemaVersion).append(',')
        append("\"id\":").append(id.canonicalJsonString()).append(',')
        append("\"layout\":").append(layout.canonicalJson()).append(',')
        append("\"budgets\":").append(budgets.canonicalJson()).append(',')
        append("\"adapterConfiguration\":{")
        append(adapterConfiguration.entries.joinToString(",") { (key, values) ->
            key.canonicalJsonString() + ":[" + values.joinToString(",") { it.canonicalJsonString() } + "]"
        })
        append("}}")
    }

    companion object {
        const val CURRENT_SCHEMA_VERSION = 1
    }
}

internal fun requireNormalizedProjectPath(value: String, subject: String): String {
    require(
        value.isNotBlank() && value.length <= 4_096 && !value.startsWith('/') && '\\' !in value &&
            value.none { it.code < 0x20 || it.code == 0x7f || it == ':' },
    ) { "$subject is not a normalized relative path: $value" }
    require(value.split('/').none { it.isBlank() || it == "." || it == ".." || it.length > 255 }) {
        "$subject is not a normalized relative path: $value"
    }
    return value
}

private fun compileTemplateMatcher(template: String): Regex {
    val pattern = buildString {
        append('^')
        var cursor = 0
        PATH_PLACEHOLDER.findAll(template).forEach { placeholder ->
            append(Regex.escape(template.substring(cursor, placeholder.range.first)))
            append("[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")
            cursor = placeholder.range.last + 1
        }
        append(Regex.escape(template.substring(cursor)))
        append('$')
    }
    return Regex(pattern)
}

private fun String.canonicalJsonString(): String = buildString {
    append('"')
    this@canonicalJsonString.forEach { character ->
        when (character) {
            '\\' -> append("\\\\")
            '"' -> append("\\\"")
            '\b' -> append("\\b")
            '\u000c' -> append("\\f")
            '\n' -> append("\\n")
            '\r' -> append("\\r")
            '\t' -> append("\\t")
            else -> if (character.code < 0x20) append("\\u%04x".format(character.code)) else append(character)
        }
    }
    append('"')
}

private val PROFILE_ID = Regex("[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")
private val PROFILE_COMPONENT = Regex("[a-z][a-z0-9-]{0,63}")
private val CONFIGURATION_KEY = Regex("[a-z][a-z0-9.-]{0,127}")
private val PATH_PLACEHOLDER = Regex("\\{([a-z][a-z0-9_-]{0,63})}")
private val PATH_PARAMETER = Regex("[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")
