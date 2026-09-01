package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.nio.charset.StandardCharsets
import java.util.Collections
import java.util.TreeSet
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class FullTreeClangHeaderTraceException(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

/** Caller-lowerable ceilings beneath the immutable Clang direct-header trace policy. */
internal data class FullTreeClangHeaderTraceLimits(
    val maximumInputBytes: Int = CLANG_TRACE_MAXIMUM_INPUT_BYTES,
    val maximumDependencyFiles: Int = CLANG_TRACE_MAXIMUM_DEPENDENCY_FILES,
    val maximumIncludeOccurrences: Int = CLANG_TRACE_MAXIMUM_INCLUDE_OCCURRENCES,
    val maximumModuleImports: Int = CLANG_TRACE_MAXIMUM_MODULE_IMPORTS,
    val maximumPathBytes: Int = CLANG_TRACE_MAXIMUM_PATH_BYTES,
    val maximumWorkUnits: Long = CLANG_TRACE_MAXIMUM_WORK_UNITS,
) {
    init {
        require(maximumInputBytes in 1..CLANG_TRACE_MAXIMUM_INPUT_BYTES)
        require(maximumDependencyFiles in 1..CLANG_TRACE_MAXIMUM_DEPENDENCY_FILES)
        require(maximumIncludeOccurrences in 1..CLANG_TRACE_MAXIMUM_INCLUDE_OCCURRENCES)
        require(maximumModuleImports in 1..CLANG_TRACE_MAXIMUM_MODULE_IMPORTS)
        require(maximumPathBytes in 1..CLANG_TRACE_MAXIMUM_PATH_BYTES)
        require(maximumWorkUnits in 1L..CLANG_TRACE_MAXIMUM_WORK_UNITS)
    }
}

/**
 * One authenticated logical root in Clang's observed path namespace.
 *
 * The compiler coordinator, not this parser, proves the physical identity behind [observedRoot].
 * This type only performs a strict, segment-aware projection into `source/` or `generated/`.
 */
internal data class FullTreeClangTraceRoot(
    val observedRoot: String,
    val canonicalRoot: String,
) {
    init {
        require(observedRoot.startsWith('/') && observedRoot.length > 1)
        require(!observedRoot.endsWith('/'))
        require(isCanonicalTraceAbsolutePath(observedRoot))
        require(canonicalRoot == "source" || canonicalRoot == "generated")
    }
}

internal data class FullTreeClangIncludeOccurrence(
    val consumerPath: String,
    val presumedLocationFile: String,
    val line: Long,
    val column: Long,
    val dependencyPath: String,
)

internal data class FullTreeClangExternalIncludeOccurrence(
    val consumerPath: String,
    val presumedLocationFile: String,
    val line: Long,
    val column: Long,
    val observedDependencyPath: String,
)

internal data class FullTreeClangExternalConsumerIncludeOccurrence(
    val observedConsumerPath: String,
    val presumedLocationFile: String,
    val line: Long,
    val column: Long,
    val observedDependencyPath: String,
    val dependencyProjectPath: String?,
)

internal data class FullTreeClangModuleImport(
    val consumerPath: String,
    val presumedLocationFile: String,
    val line: Long,
    val column: Long,
    val moduleName: String,
    val observedModuleMapPath: String,
    val moduleMapPath: String?,
)

internal data class FullTreeClangExternalConsumerModuleImport(
    val observedConsumerPath: String,
    val presumedLocationFile: String,
    val line: Long,
    val column: Long,
    val moduleName: String,
    val observedModuleMapPath: String,
    val moduleMapProjectPath: String?,
)

/** Strictly parsed Clang `direct-per-file` JSON. No compiler-authenticity claim lives here. */
internal data class FullTreeClangHeaderTrace(
    val inputSha256: String,
    val canonicalFactsSha256: String,
    val dependencyFileCount: Int,
    val externalFiles: List<String>,
    val includeOccurrences: List<FullTreeClangIncludeOccurrence>,
    val externalIncludeOccurrences: List<FullTreeClangExternalIncludeOccurrence>,
    val externalConsumerIncludeOccurrences: List<FullTreeClangExternalConsumerIncludeOccurrence>,
    val moduleImports: List<FullTreeClangModuleImport>,
    val externalConsumerModuleImports: List<FullTreeClangExternalConsumerModuleImport>,
    val projectFiles: List<String>,
    val workUnits: Long,
)

/**
 * Bounded parser for Clang 22's structured direct include output.
 *
 * It intentionally does not execute Clang and does not accept callbacks, parsed JSON, or caller
 * supplied edges. The production coordinator must retain and authenticate the compiler, roots,
 * command, environment, generated overlay, exit status, and this exact byte payload before these
 * facts can be admitted to an oracle control.
 */
internal object FullTreeClangHeaderTraceParser {
    fun parse(
        bytes: ByteArray,
        roots: List<FullTreeClangTraceRoot>,
        expectedMainSourcePath: String,
        limits: FullTreeClangHeaderTraceLimits = FullTreeClangHeaderTraceLimits(),
    ): FullTreeClangHeaderTrace = try {
        parseTrace(bytes, roots, expectedMainSourcePath, limits)
    } catch (failure: FullTreeClangHeaderTraceException) {
        throw failure
    } catch (failure: Exception) {
        throw FullTreeClangHeaderTraceException(
            "Clang direct-header trace parsing failed: ${failure.message}",
            failure,
        )
    }
}

private fun parseTrace(
    source: ByteArray,
    requestedRoots: List<FullTreeClangTraceRoot>,
    expectedMainSourcePath: String,
    limits: FullTreeClangHeaderTraceLimits,
): FullTreeClangHeaderTrace {
    if (source.size > limits.maximumInputBytes) traceFail("trace byte bound exceeded")
    val bytes = source.copyOf()
    val roots = validateTraceRoots(requestedRoots)
    requireCanonicalProjectTracePath(expectedMainSourcePath, limits.maximumPathBytes, "expected main source")
    if (bytes.isEmpty()) {
        val canonicalFacts = canonicalTraceFacts(expectedMainSourcePath, emptyList(), limits)
        return FullTreeClangHeaderTrace(
            inputSha256 = OracleArtifacts.sha256(bytes),
            canonicalFactsSha256 = OracleArtifacts.sha256(canonicalFacts),
            dependencyFileCount = 0,
            externalFiles = emptyList(),
            includeOccurrences = emptyList(),
            externalIncludeOccurrences = emptyList(),
            externalConsumerIncludeOccurrences = emptyList(),
            moduleImports = emptyList(),
            externalConsumerModuleImports = emptyList(),
            projectFiles = emptyList(),
            workUnits = 1,
        )
    }
    val document = OracleJson.parse(bytes, traceJsonLimits(limits)) as? JsonObject
        ?: traceFail("trace root must be an object")
    document.requireExactKeys(setOf("dependencies", "version"), "trace root")
    if (document.requiredTraceString("version") != "2.0.0") {
        traceFail("trace version must be 2.0.0")
    }
    val dependencies = document.requiredTraceArray("dependencies")
    if (dependencies.isEmpty()) {
        traceFail("Clang represents a no-dependency translation unit with an empty output file")
    }
    if (dependencies.size > limits.maximumDependencyFiles) traceFail("dependency-file bound exceeded")

    val records = ArrayList<ParsedTraceDependencyRecord>(dependencies.size)
    val projectFiles = TreeSet(FULL_TREE_CODE_POINT_ORDER)
    val externalFiles = TreeSet(FULL_TREE_CODE_POINT_ORDER)
    val dependencySources = HashSet<String>()
    var rawIncludeOccurrences = 0
    var rawModuleImports = 0
    var workUnits = 1L

    dependencies.forEachIndexed { dependencyIndex, element ->
        workUnits = chargeTraceWork(workUnits, 1, limits)
        val dependency = element as? JsonObject
            ?: traceFail("dependency record $dependencyIndex must be an object")
        dependency.requireExactKeys(setOf("imports", "includes", "source"), "dependency record")
        val observedConsumer = dependency.requiredTraceString("source").validatedObservedPath(limits)
        if (!dependencySources.add(observedConsumer)) traceFail("trace repeats a dependency source")
        val consumer = projectPath(observedConsumer, roots)
        if (consumer != null) projectFiles += consumer else externalFiles += observedConsumer
        val recordOccurrences = ArrayList<FullTreeClangIncludeOccurrence>()
        val recordExternalOccurrences = ArrayList<FullTreeClangExternalIncludeOccurrence>()
        val recordExternalConsumerOccurrences = ArrayList<FullTreeClangExternalConsumerIncludeOccurrence>()
        val recordImports = ArrayList<FullTreeClangModuleImport>()
        val recordExternalConsumerImports = ArrayList<FullTreeClangExternalConsumerModuleImport>()
        val canonicalIncludes = ArrayList<JsonObject>()
        val canonicalImports = ArrayList<JsonObject>()

        dependency.requiredTraceArray("includes").forEachIndexed { includeIndex, includeElement ->
            workUnits = chargeTraceWork(workUnits, 1, limits)
            rawIncludeOccurrences++
            if (rawIncludeOccurrences > limits.maximumIncludeOccurrences) {
                traceFail("include-occurrence bound exceeded")
            }
            val include = includeElement as? JsonObject
                ?: traceFail("include record $dependencyIndex/$includeIndex must be an object")
            include.requireExactKeys(setOf("file", "location"), "include record")
            val location = parseTraceLocation(include.requiredTraceString("location"), limits)
            val observedDependency = include.requiredTraceString("file").validatedObservedPath(limits)
            val dependencyPath = projectPath(observedDependency, roots)
            if (dependencyPath != null) projectFiles += dependencyPath else externalFiles += observedDependency
            canonicalIncludes += JsonObject(
                mapOf(
                    "dependency" to JsonPrimitive(dependencyPath ?: observedDependency),
                    "dependencyKind" to JsonPrimitive(if (dependencyPath == null) "external" else "project"),
                    "locationColumn" to JsonPrimitive(location.column),
                    "locationFile" to JsonPrimitive(location.path),
                    "locationFileKind" to JsonPrimitive("opaque-presumed-label"),
                    "locationLine" to JsonPrimitive(location.line),
                ),
            )
            if (consumer == null) {
                recordExternalConsumerOccurrences += FullTreeClangExternalConsumerIncludeOccurrence(
                    observedConsumer,
                    location.path,
                    location.line,
                    location.column,
                    observedDependency,
                    dependencyPath,
                )
            } else if (dependencyPath != null) {
                recordOccurrences += FullTreeClangIncludeOccurrence(
                    consumer,
                    location.path,
                    location.line,
                    location.column,
                    dependencyPath,
                )
            } else {
                recordExternalOccurrences += FullTreeClangExternalIncludeOccurrence(
                    consumer,
                    location.path,
                    location.line,
                    location.column,
                    observedDependency,
                )
            }
        }

        dependency.requiredTraceArray("imports").forEachIndexed { importIndex, importElement ->
            workUnits = chargeTraceWork(workUnits, 1, limits)
            rawModuleImports++
            if (rawModuleImports > limits.maximumModuleImports) traceFail("module-import bound exceeded")
            val imported = importElement as? JsonObject
                ?: traceFail("import record $dependencyIndex/$importIndex must be an object")
            imported.requireExactKeys(setOf("file", "location", "module"), "import record")
            val location = parseTraceLocation(imported.requiredTraceString("location"), limits)
            val module = imported.requiredTraceString("module")
            requireBoundedTraceScalar(module, limits.maximumPathBytes, "module name")
            val moduleMap = imported.requiredTraceString("file").validatedObservedPath(limits)
            val canonicalModuleMap = projectPath(moduleMap, roots)
            if (canonicalModuleMap != null) projectFiles += canonicalModuleMap else externalFiles += moduleMap
            canonicalImports += JsonObject(
                mapOf(
                    "locationColumn" to JsonPrimitive(location.column),
                    "locationFile" to JsonPrimitive(location.path),
                    "locationFileKind" to JsonPrimitive("opaque-presumed-label"),
                    "locationLine" to JsonPrimitive(location.line),
                    "module" to JsonPrimitive(module),
                    "moduleMap" to JsonPrimitive(canonicalModuleMap ?: moduleMap),
                    "moduleMapKind" to JsonPrimitive(if (canonicalModuleMap == null) "external" else "project"),
                ),
            )
            if (consumer == null) {
                recordExternalConsumerImports += FullTreeClangExternalConsumerModuleImport(
                    observedConsumer,
                    location.path,
                    location.line,
                    location.column,
                    module,
                    moduleMap,
                    canonicalModuleMap,
                )
            } else {
                recordImports += FullTreeClangModuleImport(
                    consumer,
                    location.path,
                    location.line,
                    location.column,
                    module,
                    moduleMap,
                    canonicalModuleMap,
                )
            }
        }
        if (canonicalIncludes.isEmpty() && canonicalImports.isEmpty()) {
            traceFail("Clang direct-per-file output contains an impossible empty dependency record")
        }
        records += ParsedTraceDependencyRecord(
            observedConsumer,
            consumer ?: observedConsumer,
            recordOccurrences,
            recordExternalOccurrences,
            recordExternalConsumerOccurrences,
            recordImports,
            recordExternalConsumerImports,
            JsonObject(
                mapOf(
                    "imports" to JsonArray(canonicalImports),
                    "includes" to JsonArray(canonicalIncludes),
                    "source" to JsonPrimitive(consumer ?: observedConsumer),
                ),
            ),
        )
    }

    val orderedRecords = records.sortedWith(compareBy(FULL_TREE_CODE_POINT_ORDER) { it.canonicalConsumer })
    val occurrences = orderedRecords.flatMap { it.occurrences }
    val externalOccurrences = orderedRecords.flatMap { it.externalOccurrences }
    val externalConsumerOccurrences = orderedRecords.flatMap { it.externalConsumerOccurrences }
    val imports = orderedRecords.flatMap { it.imports }
    val externalConsumerImports = orderedRecords.flatMap { it.externalConsumerImports }
    val canonicalFacts = canonicalTraceFacts(
        expectedMainSourcePath,
        orderedRecords.map { it.canonicalRecord },
        limits,
    )

    return FullTreeClangHeaderTrace(
        inputSha256 = OracleArtifacts.sha256(bytes),
        canonicalFactsSha256 = OracleArtifacts.sha256(canonicalFacts),
        dependencyFileCount = dependencies.size,
        externalFiles = immutableTraceList(externalFiles),
        includeOccurrences = immutableTraceList(occurrences),
        externalIncludeOccurrences = immutableTraceList(externalOccurrences),
        externalConsumerIncludeOccurrences = immutableTraceList(externalConsumerOccurrences),
        moduleImports = immutableTraceList(imports),
        externalConsumerModuleImports = immutableTraceList(externalConsumerImports),
        projectFiles = immutableTraceList(projectFiles),
        workUnits = workUnits,
    )
}

private fun validateTraceRoots(requested: List<FullTreeClangTraceRoot>): List<FullTreeClangTraceRoot> {
    val snapshot = ArrayList(requested)
    if (snapshot.size != 2 || snapshot.map { it.canonicalRoot }.toSet() != setOf("source", "generated")) {
        traceFail("trace roots must bind source and generated exactly once")
    }
    if (snapshot.map { it.observedRoot }.toSet().size != snapshot.size) {
        traceFail("trace roots must have distinct observed paths")
    }
    snapshot.indices.forEach { leftIndex ->
        ((leftIndex + 1) until snapshot.size).forEach { rightIndex ->
            val left = snapshot[leftIndex].observedRoot
            val right = snapshot[rightIndex].observedRoot
            if (left.startsWith(right + "/") || right.startsWith(left + "/")) {
                traceFail("trace roots may not overlap")
            }
        }
    }
    return snapshot.sortedWith(compareBy(FULL_TREE_CODE_POINT_ORDER) { it.observedRoot })
}

private fun projectPath(observed: String, roots: List<FullTreeClangTraceRoot>): String? {
    if (!isCanonicalTraceAbsolutePath(observed)) return null
    val matching = roots.filter { observed == it.observedRoot || observed.startsWith(it.observedRoot + "/") }
    if (matching.isEmpty()) return null
    if (matching.size != 1) traceFail("observed path matches multiple authenticated roots")
    val root = matching.single()
    if (observed == root.observedRoot) traceFail("trace path names a root rather than a file")
    val relative = observed.substring(root.observedRoot.length + 1)
    return "${root.canonicalRoot}/$relative"
}

private data class ParsedTraceDependencyRecord(
    val observedConsumer: String,
    val canonicalConsumer: String,
    val occurrences: List<FullTreeClangIncludeOccurrence>,
    val externalOccurrences: List<FullTreeClangExternalIncludeOccurrence>,
    val externalConsumerOccurrences: List<FullTreeClangExternalConsumerIncludeOccurrence>,
    val imports: List<FullTreeClangModuleImport>,
    val externalConsumerImports: List<FullTreeClangExternalConsumerModuleImport>,
    val canonicalRecord: JsonObject,
)

private data class TraceLocation(val path: String, val line: Long, val column: Long)

private fun parseTraceLocation(raw: String, limits: FullTreeClangHeaderTraceLimits): TraceLocation {
    requireBoundedTraceScalar(raw, limits.maximumPathBytes + 64, "include location")
    val columnSeparator = raw.lastIndexOf(':')
    val lineSeparator = if (columnSeparator > 0) raw.lastIndexOf(':', columnSeparator - 1) else -1
    if (lineSeparator < 0 || columnSeparator <= lineSeparator + 1 || columnSeparator == raw.lastIndex) {
        traceFail("include location is not filename:line:column")
    }
    val path = raw.substring(0, lineSeparator)
    if (path.toByteArray(StandardCharsets.UTF_8).size > limits.maximumPathBytes ||
        '\u0000' in path || '\n' in path || '\r' in path
    ) {
        traceFail("presumed location file exceeds its scalar bound")
    }
    val line = raw.substring(lineSeparator + 1, columnSeparator).strictTraceNumber("line", allowZero = true)
    val column = raw.substring(columnSeparator + 1).strictPositiveTraceNumber("column")
    return TraceLocation(path, line, column)
}

private fun canonicalTraceFacts(
    expectedMainSourcePath: String,
    dependencies: List<JsonObject>,
    limits: FullTreeClangHeaderTraceLimits,
): ByteArray = OracleJson.canonicalBytes(
    JsonObject(
        mapOf(
            "dependencies" to JsonArray(dependencies),
            "expectedMainSourcePath" to JsonPrimitive(expectedMainSourcePath),
            "version" to JsonPrimitive("2.0.0"),
        ),
    ),
    traceJsonLimits(limits),
)

private fun String.validatedObservedPath(limits: FullTreeClangHeaderTraceLimits): String {
    requireBoundedTraceScalar(this, limits.maximumPathBytes, "observed path")
    if (!startsWith('/') || '\\' in this) traceFail("observed path is not absolute POSIX syntax")
    if (this == "/") traceFail("observed path names the filesystem root")
    return this
}

private fun requireCanonicalProjectTracePath(path: String, maximumPathBytes: Int, label: String) {
    requireBoundedTraceScalar(path, maximumPathBytes, label)
    if (!(path.startsWith("source/") || path.startsWith("generated/")) ||
        path.split('/').any { it.isEmpty() || it == "." || it == ".." } || '\\' in path
    ) {
        traceFail("$label is not a canonical source/generated path")
    }
}

private fun String.strictPositiveTraceNumber(label: String): Long {
    return strictTraceNumber(label, allowZero = false)
}

private fun String.strictTraceNumber(label: String, allowZero: Boolean): Long {
    if (isEmpty() || length > 19 || any { it !in '0'..'9' } || (length > 1 && first() == '0')) {
        traceFail("include $label is not a canonical integer")
    }
    val value = toLongOrNull() ?: traceFail("include $label is out of range")
    if (value < 0 || (!allowZero && value == 0L)) {
        traceFail("include $label is outside its permitted range")
    }
    return value
}

private fun isCanonicalTraceAbsolutePath(path: String): Boolean =
    path.startsWith('/') && '\\' !in path && '\u0000' !in path &&
        path.split('/').drop(1).all { it.isNotEmpty() && it != "." && it != ".." }

private fun requireBoundedTraceScalar(value: String, maximumBytes: Int, label: String) {
    val bytes = value.toByteArray(StandardCharsets.UTF_8).size
    if (value.isEmpty() || '\u0000' in value || '\n' in value || '\r' in value || bytes > maximumBytes) {
        traceFail("$label is empty, non-scalar, or exceeds its byte bound")
    }
}

private fun JsonObject.requireExactKeys(expected: Set<String>, label: String) {
    if (keys != expected) traceFail("$label fields differ from the Clang JSON v2 contract")
}

private fun JsonObject.requiredTraceString(name: String): String =
    (get(name) as? JsonPrimitive)?.takeIf { it.isString }?.content
        ?: traceFail("trace field $name must be a string")

private fun JsonObject.requiredTraceArray(name: String): JsonArray =
    get(name) as? JsonArray ?: traceFail("trace field $name must be an array")

private fun chargeTraceWork(
    current: Long,
    amount: Int,
    limits: FullTreeClangHeaderTraceLimits,
): Long {
    val next = try {
        Math.addExact(current, amount.toLong())
    } catch (failure: ArithmeticException) {
        throw FullTreeClangHeaderTraceException("trace work count overflows", failure)
    }
    if (next > limits.maximumWorkUnits) traceFail("trace work-unit bound exceeded")
    return next
}

private fun <T> immutableTraceList(values: Collection<T>): List<T> =
    Collections.unmodifiableList(ArrayList(values))

private fun traceJsonLimits(limits: FullTreeClangHeaderTraceLimits): StrictJsonLimits = StrictJsonLimits(
    maximumInputBytes = limits.maximumInputBytes,
    maximumCanonicalBytes = CLANG_TRACE_MAXIMUM_CANONICAL_BYTES,
    maximumDepth = 16,
    maximumNodes = minOf(
        1_000_000,
        8 + limits.maximumDependencyFiles * 5 +
            limits.maximumIncludeOccurrences * 5 + limits.maximumModuleImports * 7,
    ),
    maximumStringBytes = limits.maximumPathBytes + 64,
    maximumTotalStringBytes = CLANG_TRACE_MAXIMUM_CANONICAL_BYTES,
)

private fun traceFail(message: String): Nothing = throw FullTreeClangHeaderTraceException(message)

internal const val CLANG_TRACE_MAXIMUM_INPUT_BYTES = 16 * 1024 * 1024
internal const val CLANG_TRACE_MAXIMUM_CANONICAL_BYTES = 64 * 1024 * 1024
internal const val CLANG_TRACE_MAXIMUM_DEPENDENCY_FILES = 50_000
internal const val CLANG_TRACE_MAXIMUM_INCLUDE_OCCURRENCES = 100_000
internal const val CLANG_TRACE_MAXIMUM_MODULE_IMPORTS = 10_000
internal const val CLANG_TRACE_MAXIMUM_PATH_BYTES = 16 * 1024
internal const val CLANG_TRACE_MAXIMUM_WORK_UNITS = 2_000_000L
