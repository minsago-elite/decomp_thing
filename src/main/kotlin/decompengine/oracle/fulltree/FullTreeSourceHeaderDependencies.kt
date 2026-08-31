package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.provenance.BoundedTarEntry
import decompengine.oracle.provenance.BoundedTarEntryKind
import decompengine.oracle.provenance.BoundedTarXzArchive
import decompengine.oracle.provenance.BoundedTarXzException
import decompengine.oracle.provenance.BoundedTarXzLimits
import decompengine.oracle.provenance.BoundedTarXzRegularFileVisitor
import decompengine.oracle.provenance.BoundedTarXzSource
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.BasicFileAttributes
import java.security.MessageDigest
import java.util.Collections
import java.util.TreeMap
import java.util.TreeSet
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class FullTreeSourceHeaderDependencyException(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

/** Caller-lowerable ceilings beneath the immutable dependency-evidence v1 policy. */
data class FullTreeSourceHeaderDependencyLimits(
    val planning: FullTreePlanningInventoryLimits = FullTreePlanningInventoryLimits(),
    val maximumIndexedRegularFiles: Int = DEPENDENCY_MAXIMUM_INDEXED_REGULAR_FILES,
    val maximumParsedFiles: Int = DEPENDENCY_MAXIMUM_PARSED_FILES,
    val maximumParsedBytes: Long = DEPENDENCY_MAXIMUM_PARSED_BYTES,
    val maximumParsedFileBytes: Long = DEPENDENCY_MAXIMUM_PARSED_FILE_BYTES,
    val maximumLogicalLineBytes: Int = DEPENDENCY_MAXIMUM_LOGICAL_LINE_BYTES,
    val maximumDirectives: Long = DEPENDENCY_MAXIMUM_DIRECTIVES,
    val maximumCandidatesPerDirective: Int = DEPENDENCY_MAXIMUM_CANDIDATES_PER_DIRECTIVE,
    val maximumOutputRecords: Int = DEPENDENCY_MAXIMUM_OUTPUT_RECORDS,
    val maximumWorkUnits: Long = DEPENDENCY_MAXIMUM_WORK_UNITS,
    val maximumSerializedBytes: Int = DEPENDENCY_MAXIMUM_SERIALIZED_BYTES,
) {
    init {
        require(maximumIndexedRegularFiles in 1..DEPENDENCY_MAXIMUM_INDEXED_REGULAR_FILES)
        require(maximumParsedFiles in 1..DEPENDENCY_MAXIMUM_PARSED_FILES)
        require(maximumParsedBytes in 1L..DEPENDENCY_MAXIMUM_PARSED_BYTES)
        require(maximumParsedFileBytes in 1L..DEPENDENCY_MAXIMUM_PARSED_FILE_BYTES)
        require(maximumLogicalLineBytes in 1..DEPENDENCY_MAXIMUM_LOGICAL_LINE_BYTES)
        require(maximumDirectives in 1L..DEPENDENCY_MAXIMUM_DIRECTIVES)
        require(maximumCandidatesPerDirective in 1..DEPENDENCY_MAXIMUM_CANDIDATES_PER_DIRECTIVE)
        require(maximumOutputRecords in 1..DEPENDENCY_MAXIMUM_OUTPUT_RECORDS)
        require(maximumWorkUnits in 1L..DEPENDENCY_MAXIMUM_WORK_UNITS)
        require(maximumSerializedBytes in 1..DEPENDENCY_MAXIMUM_SERIALIZED_BYTES)
    }
}

/** Immutable, explicitly planning-only source/header dependency evidence. */
sealed interface FullTreeSourceHeaderDependencyAssessment {
    val reportSha256: String
    val directiveCount: Long
    val resolvedLocalReferenceCount: Long
    val canonicalBytes: ByteArray
}

/**
 * Bounded Kotlin/JVM projection of authenticated planning/source/archive inputs into conservative
 * direct source/header dependency evidence.
 *
 * This is deliberately not a compiler include resolver or build-graph authority. Only a literal,
 * unconditional quoted include whose lexical path relative to the including file's directory
 * targets an authenticated regular archive file becomes a resolved local file reference. All
 * other forms remain explicitly conditional, candidate, unresolved, macro, nonstandard, or
 * malformed evidence.
 */
object FullTreeSourceHeaderDependencies {
    val configurationSha256: String by lazy {
        OracleSchemas.configurationSha256(DEPENDENCY_SCHEMA, DEPENDENCY_POLICY)
    }

    fun assess(
        sourceArchivePath: Path,
        scopePath: Path,
        sourceLockPath: Path,
        artifactManifestPath: Path,
        buildRecordPath: Path,
        inventoryPath: Path,
        sourceInventoryPath: Path,
        planningInventoryPath: Path,
        limits: FullTreeSourceHeaderDependencyLimits = FullTreeSourceHeaderDependencyLimits(),
    ): FullTreeSourceHeaderDependencyAssessment = try {
        ValidatedAssessment.create(
            sourceArchivePath,
            scopePath,
            sourceLockPath,
            artifactManifestPath,
            buildRecordPath,
            inventoryPath,
            sourceInventoryPath,
            planningInventoryPath,
            limits,
        )
    } catch (failure: FullTreeSourceHeaderDependencyException) {
        throw failure
    } catch (failure: Exception) {
        throw FullTreeSourceHeaderDependencyException(
            "full-tree source/header dependency assessment failed: ${failure.message}",
            failure,
        )
    }

    /**
     * The JVM-visible synthetic bridge can accept only raw paths and lowering limits. It has no
     * parsed-state, registry, archive-index, callback, digest, or assessment constructor seam.
     */
    private class ValidatedAssessment private constructor(
        sourceArchivePath: Path,
        scopePath: Path,
        sourceLockPath: Path,
        artifactManifestPath: Path,
        buildRecordPath: Path,
        inventoryPath: Path,
        sourceInventoryPath: Path,
        planningInventoryPath: Path,
        limits: FullTreeSourceHeaderDependencyLimits,
    ) : FullTreeSourceHeaderDependencyAssessment {
        private val state = assessDependencies(
            DependencyPaths(
                sourceArchivePath,
                scopePath,
                sourceLockPath,
                artifactManifestPath,
                buildRecordPath,
                inventoryPath,
                sourceInventoryPath,
                planningInventoryPath,
            ),
            limits,
        )

        override val reportSha256: String = state.reportSha256
        override val directiveCount: Long = state.directiveCount
        override val resolvedLocalReferenceCount: Long = state.resolvedLocalReferenceCount
        override val canonicalBytes: ByteArray
            get() = state.bytes.copyOf()

        companion object {
            fun create(
                sourceArchivePath: Path,
                scopePath: Path,
                sourceLockPath: Path,
                artifactManifestPath: Path,
                buildRecordPath: Path,
                inventoryPath: Path,
                sourceInventoryPath: Path,
                planningInventoryPath: Path,
                limits: FullTreeSourceHeaderDependencyLimits,
            ): FullTreeSourceHeaderDependencyAssessment = ValidatedAssessment(
                sourceArchivePath,
                scopePath,
                sourceLockPath,
                artifactManifestPath,
                buildRecordPath,
                inventoryPath,
                sourceInventoryPath,
                planningInventoryPath,
                limits,
            )
        }
    }
}

private fun assessDependencies(
    paths: DependencyPaths,
    limits: FullTreeSourceHeaderDependencyLimits,
): DependencyAssessmentState {
    requireDistinctDependencyInputs(paths)
    val registry = loadDependencyPlanningRegistry(paths, limits)
    val (planningDocument, planningBytes) = readCanonicalControlObject(
        paths.planningInventory,
        limits.planning.maximumSerializedBytes,
        "full-tree planning inventory",
        "full-tree-planning-inventory",
    )
    if (OracleArtifacts.sha256(planningBytes) != registry.artifactSha256) {
        dependencyFailure("planning inventory changed after authenticated registry admission")
    }
    val planningOracle = planningDocument.controlObject("oracle")
    val scope = FullTreeScopeControl.load(
        paths.scope,
        paths.sourceLock,
        paths.artifactManifest,
        limits.planning.control,
    )
    val archiveRecord = scope.sourceLock.controlObject("source").controlObject("archive")
    val expectedArchiveBytes = archiveRecord.controlLong("bytes")
    val expectedArchiveSha256 = archiveRecord.controlString("sha256")
    requireDependencyDigest(expectedArchiveSha256, "source archive")
    val archiveRoot = scope.sourceLock.controlObject("source").controlString("archiveRoot")
    val archiveCommit = scope.sourceLock.controlObject("revision").controlString("commit")

    val sourceOnlyPaths = TreeSet(FULL_TREE_CODE_POINT_ORDER)
    val modulePaths = HashSet<String>()
    val plannedArchivePaths = HashSet<String>()
    val enabledRoots = TreeSet(FULL_TREE_CODE_POINT_ORDER)
    val moduleIds = HashSet<String>()
    registry.sourceModules.forEach { module ->
        if (!moduleIds.add(module.moduleId) || module.moduleId != module.unitId) {
            dependencyFailure("planning registry repeats or aliases a source module")
        }
        if (!modulePaths.add(module.sourcePath)) {
            dependencyFailure("planning registry repeats a module source path")
        }
        when (module.sourceKind) {
            "handwritten" -> sourceToArchivePath(module.sourcePath).also { relative ->
                plannedArchivePaths += relative
                enabledRoots += relative.substringBefore('/')
            }
            "generated" -> requireGeneratedSourcePath(module.sourcePath)
            else -> dependencyFailure("planning registry contains an unsupported source kind")
        }
    }
    if (registry.sourceModules.isEmpty()) dependencyFailure("planning registry has no source modules")
    registry.sourceOnlyUnits.forEach { unit ->
        if (!sourceOnlyPaths.add(unit.sourcePath) || unit.sourcePath in modulePaths) {
            dependencyFailure("planning source-only evidence is duplicated or owns a module path")
        }
        val relative = sourceToArchivePath(unit.sourcePath)
        plannedArchivePaths += relative
        enabledRoots += relative.substringBefore('/')
        val sourceOnlyId = FullTreeInventoryControl.compilationUnitId(unit.sourcePath)
        if (sourceOnlyId in moduleIds) {
            dependencyFailure("planning source-only evidence collides with a module owner")
        }
    }
    if (enabledRoots.isEmpty()) dependencyFailure("planning registry has no authenticated source roots")

    val archive = StableControlFile.open(
        paths.sourceArchive,
        minOf(expectedArchiveBytes, limits.planning.control.maximumSourceArchiveBytes),
        "source archive",
    )
    try {
        if (archive.size != expectedArchiveBytes) {
            dependencyFailure("source archive byte count differs from its lock")
        }
        val archiveSha256 = archive.sha256(label = "source archive")
        if (archiveSha256 != expectedArchiveSha256) dependencyFailure("source archive differs from its lock")

        val collector = DependencyArchiveCollector(plannedArchivePaths, enabledRoots, limits)
        val archiveSummary = try {
            BoundedTarXzArchive.scan(
                source = object : BoundedTarXzSource {
                    override val size: Long = archive.size

                    override fun read(
                        position: Long,
                        destination: ByteArray,
                        offset: Int,
                        length: Int,
                    ): Int = archive.readAt(position, destination, offset, length)
                },
                expectedRoot = archiveRoot,
                expectedCommit = archiveCommit,
                limits = dependencyArchiveLimits(limits),
                regularFileVisitor = collector,
                onEntry = collector::onEntry,
            )
        } catch (failure: BoundedTarXzException) {
            throw FullTreeSourceHeaderDependencyException(
                failure.message ?: "source archive violates its strict profile",
                failure,
            )
        }
        val archiveEvidence = collector.finish(archiveSummary)
        plannedArchivePaths.forEach { required ->
            if (required !in archiveEvidence.regularPaths) {
                dependencyFailure("planned handwritten/source-only input is absent from the authenticated archive: $required")
            }
            if (required !in archiveEvidence.parsedFiles) {
                dependencyFailure("planned handwritten/source-only input was not parsed: $required")
            }
        }

        val resolvedFiles = resolveArchiveDependencyFiles(archiveEvidence, limits)
        val projection = buildDependencyProjection(
            registry,
            planningOracle,
            archiveEvidence,
            resolvedFiles,
            archiveSummary,
            archiveRoot,
            archiveCommit,
            expectedArchiveBytes,
            expectedArchiveSha256,
            limits,
        )
        val bytes = canonicalDependencyBytes(projection.document, limits.maximumSerializedBytes)
        validateDependencySchema(projection.document)

        val terminalArchiveSha256 = archive.sha256(label = "terminal source archive")
        if (terminalArchiveSha256 != expectedArchiveSha256) {
            dependencyFailure("source archive changed before terminal assessment acceptance")
        }
        archive.verifyUnchanged("source archive")
        terminallyReauthenticatePlanning(paths, limits, registry)
        return DependencyAssessmentState(
            reportSha256 = projection.document.controlString("reportSha256"),
            directiveCount = projection.directiveCount,
            resolvedLocalReferenceCount = projection.resolvedLocalReferenceCount,
            bytes = bytes.copyOf(),
        )
    } finally {
        archive.close()
    }
}

private fun loadDependencyPlanningRegistry(
    paths: DependencyPaths,
    limits: FullTreeSourceHeaderDependencyLimits,
): AuthenticatedFullTreePlanningRegistry = FullTreePlanningInventoryControl.loadAndValidate(
    paths.planningInventory,
    paths.scope,
    paths.sourceLock,
    paths.artifactManifest,
    paths.buildRecord,
    paths.inventory,
    paths.sourceInventory,
    limits.planning,
)

private fun terminallyReauthenticatePlanning(
    paths: DependencyPaths,
    limits: FullTreeSourceHeaderDependencyLimits,
    initial: AuthenticatedFullTreePlanningRegistry,
) {
    val terminal = loadDependencyPlanningRegistry(paths, limits)
    if (terminal.artifactSha256 != initial.artifactSha256 ||
        terminal.reportSha256 != initial.reportSha256 ||
        terminal.configurationSha256 != initial.configurationSha256 ||
        terminal.sourceModules.map(::moduleIdentityFields) != initial.sourceModules.map(::moduleIdentityFields) ||
        terminal.sourceOnlyUnits.map(::sourceOnlyIdentityFields) != initial.sourceOnlyUnits.map(::sourceOnlyIdentityFields)
    ) {
        dependencyFailure("planning inputs changed before terminal assessment acceptance")
    }
}

private fun moduleIdentityFields(module: FullTreePlanningSourceModule): List<String> =
    listOf(module.moduleId, module.unitId, module.shardId, module.sourceKind, module.sourcePath)

private fun sourceOnlyIdentityFields(unit: FullTreePlanningSourceOnlyUnit): List<String> =
    listOf(unit.sourcePath, unit.shardId, unit.reasonCode)

private class DependencyArchiveCollector(
    private val plannedArchivePaths: Set<String>,
    private val enabledRoots: Set<String>,
    private val limits: FullTreeSourceHeaderDependencyLimits,
) : BoundedTarXzRegularFileVisitor {
    private val regularPaths = TreeSet(FULL_TREE_CODE_POINT_ORDER)
    private val parsedFiles = TreeMap<String, ParsedArchiveDependencyFile>(FULL_TREE_CODE_POINT_ORDER)
    private var activeEntry: BoundedTarEntry? = null
    private var activeParser: SourceHeaderDirectiveParser? = null
    private var parsedBytes = 0L
    private var directiveCount = 0L

    fun onEntry(entry: BoundedTarEntry) {
        if (entry.kind != BoundedTarEntryKind.REGULAR || !isWithinEnabledRoots(entry.relativePath, enabledRoots)) return
        if (!regularPaths.add(entry.relativePath)) dependencyFailure("dependency archive index repeats a regular path")
        if (regularPaths.size > limits.maximumIndexedRegularFiles) {
            dependencyFailure("dependency archive index exceeds its regular-file bound")
        }
    }

    override fun wants(entry: BoundedTarEntry): Boolean {
        if (!isWithinEnabledRoots(entry.relativePath, enabledRoots)) return false
        if (entry.relativePath !in plannedArchivePaths && !isDependencyPayloadPath(entry.relativePath)) return false
        if (activeEntry != null || activeParser != null) dependencyFailure("dependency archive visitor reentered")
        if (entry.size > limits.maximumParsedFileBytes) {
            dependencyFailure("dependency source file exceeds its individual byte bound: ${entry.relativePath}")
        }
        parsedBytes = addDependencyCount(parsedBytes, entry.size, "parsed source byte")
        if (parsedBytes > limits.maximumParsedBytes) {
            dependencyFailure("dependency source files exceed their aggregate byte bound")
        }
        if (parsedFiles.size >= limits.maximumParsedFiles) {
            dependencyFailure("dependency source files exceed their file-count bound")
        }
        val remainingDirectives = limits.maximumDirectives - directiveCount
        activeEntry = entry
        activeParser = SourceHeaderDirectiveParser(
            sourcePath = archiveToSourcePath(entry.relativePath),
            maximumLogicalLineBytes = limits.maximumLogicalLineBytes,
            maximumDirectives = remainingDirectives,
        )
        return true
    }

    override fun onChunk(
        entry: BoundedTarEntry,
        bytes: ByteArray,
        length: Int,
        endOfEntry: Boolean,
    ) {
        val expected = activeEntry ?: dependencyFailure("dependency archive visitor has no active entry")
        if (entry.path != expected.path || length !in 0..bytes.size) {
            dependencyFailure("dependency archive visitor received a mismatched chunk")
        }
        val parser = activeParser ?: dependencyFailure("dependency archive visitor has no active parser")
        parser.accept(bytes, length, endOfEntry)
        if (endOfEntry) {
            val parsed = parser.finish(entry.relativePath, entry.size)
            directiveCount = addDependencyCount(
                directiveCount,
                parsed.directives.size.toLong(),
                "dependency directive",
            )
            if (directiveCount > limits.maximumDirectives) {
                dependencyFailure("dependency directives exceed their count bound")
            }
            if (parsedFiles.put(entry.relativePath, parsed) != null) {
                dependencyFailure("dependency archive visitor repeats a parsed path")
            }
            activeEntry = null
            activeParser = null
        }
    }

    fun finish(summary: decompengine.oracle.provenance.BoundedTarXzSummary): DependencyArchiveEvidence {
        if (activeEntry != null || activeParser != null) dependencyFailure("dependency archive visitor ended mid-file")
        return DependencyArchiveEvidence(
            regularPaths = Collections.unmodifiableSet(TreeSet(FULL_TREE_CODE_POINT_ORDER).apply { addAll(regularPaths) }),
            parsedFiles = Collections.unmodifiableMap(TreeMap<String, ParsedArchiveDependencyFile>(FULL_TREE_CODE_POINT_ORDER).apply {
                putAll(parsedFiles)
            }),
            parsedBytes = parsedBytes,
            directiveCount = directiveCount,
            relevantRegularPathCommitmentSha256 = commitStrings(
                "full-tree-source-header-dependencies-v1",
                "relevant-regular-archive-paths",
                regularPaths,
            ),
            archiveMembers = summary.memberCount,
        )
    }
}

private fun resolveArchiveDependencyFiles(
    archive: DependencyArchiveEvidence,
    limits: FullTreeSourceHeaderDependencyLimits,
): Map<String, ResolvedArchiveDependencyFile> {
    val candidateIndex = TreeMap<String, MutableList<String>>(FULL_TREE_CODE_POINT_ORDER)
    archive.regularPaths.forEach { path ->
        dependencyCandidateKeys(path).forEach { key ->
            val candidates = candidateIndex.computeIfAbsent(key) { arrayListOf() }
            candidates += path
        }
    }
    candidateIndex.values.forEach { it.sortWith(FULL_TREE_CODE_POINT_ORDER) }

    return TreeMap<String, ResolvedArchiveDependencyFile>(FULL_TREE_CODE_POINT_ORDER).apply {
        archive.parsedFiles.forEach { (archivePath, file) ->
            val resolved = file.directives.map { directive ->
                resolveDirective(
                    archivePath,
                    file.structureBalanced,
                    directive,
                    archive.regularPaths,
                    candidateIndex,
                    limits.maximumCandidatesPerDirective,
                )
            }
            put(archivePath, ResolvedArchiveDependencyFile(file, resolved))
        }
    }
}

internal enum class SourceHeaderDependencyStatus(val wireName: String) {
    RESOLVED_LOCAL("resolved-local"),
    UNIQUE_ARCHIVE_CANDIDATE("unique-archive-candidate"),
    AMBIGUOUS_ARCHIVE_CANDIDATE("ambiguous-archive-candidate"),
    UNRESOLVED_ARCHIVE("unresolved-archive"),
    CONDITIONAL("conditional"),
    MACRO("macro"),
    NONSTANDARD("nonstandard"),
    MALFORMED("malformed"),
}

internal data class SourceHeaderDependencyDirective(
    val line: Long,
    val directive: String,
    val operandKind: String,
    val spelling: String?,
    val structurallyConditional: Boolean,
)

internal data class ResolvedSourceHeaderDependencyDirective(
    val raw: SourceHeaderDependencyDirective,
    val status: SourceHeaderDependencyStatus,
    val targets: List<String>,
)

/** Test-visible bounded parser seam; production always obtains bytes through the strict archive. */
internal fun parseSourceHeaderDependencyDirectives(
    sourcePath: String,
    bytes: ByteArray,
    maximumLogicalLineBytes: Int = DEPENDENCY_MAXIMUM_LOGICAL_LINE_BYTES,
    maximumDirectives: Long = DEPENDENCY_MAXIMUM_DIRECTIVES,
): Pair<Boolean, List<SourceHeaderDependencyDirective>> {
    val parser = SourceHeaderDirectiveParser(sourcePath, maximumLogicalLineBytes, maximumDirectives)
    parser.accept(bytes, bytes.size, true)
    val parsed = parser.finish(sourcePath.removePrefix("source/"), bytes.size.toLong())
    return parsed.structureBalanced to parsed.directives
}

/** Test-visible exact policy seam; no production caller can inject its result into an assessment. */
internal fun resolveSourceHeaderDependencyDirectives(
    currentArchivePath: String,
    structureBalanced: Boolean,
    directives: List<SourceHeaderDependencyDirective>,
    regularArchivePaths: Set<String>,
    maximumCandidatesPerDirective: Int = DEPENDENCY_MAXIMUM_CANDIDATES_PER_DIRECTIVE,
): List<ResolvedSourceHeaderDependencyDirective> {
    val candidates = TreeMap<String, MutableList<String>>(FULL_TREE_CODE_POINT_ORDER)
    regularArchivePaths.sortedWith(FULL_TREE_CODE_POINT_ORDER).forEach { path ->
        dependencyCandidateKeys(path).forEach { key ->
            val values = candidates.computeIfAbsent(key) { arrayListOf() }
            values += path
        }
    }
    return directives.map { directive ->
        resolveDirective(
            currentArchivePath,
            structureBalanced,
            directive,
            regularArchivePaths,
            candidates,
            maximumCandidatesPerDirective,
        )
    }
}

private fun resolveDirective(
    currentArchivePath: String,
    structureBalanced: Boolean,
    directive: SourceHeaderDependencyDirective,
    regularPaths: Set<String>,
    candidateIndex: Map<String, List<String>>,
    maximumCandidatesPerDirective: Int,
): ResolvedSourceHeaderDependencyDirective {
    fun result(status: SourceHeaderDependencyStatus, targets: List<String> = emptyList()) =
        ResolvedSourceHeaderDependencyDirective(
            directive,
            status,
            targets.map(::archiveToSourcePath).sortedWith(FULL_TREE_CODE_POINT_ORDER),
        )

    if (!structureBalanced || directive.structurallyConditional) {
        return result(SourceHeaderDependencyStatus.CONDITIONAL)
    }
    if (directive.directive != "include") return result(SourceHeaderDependencyStatus.NONSTANDARD)
    when (directive.operandKind) {
        "malformed" -> return result(SourceHeaderDependencyStatus.MALFORMED)
        "macro" -> return result(SourceHeaderDependencyStatus.MACRO)
    }
    val spelling = directive.spelling ?: return result(SourceHeaderDependencyStatus.MALFORMED)
    if (!isSafeIncludeSpelling(spelling)) return result(SourceHeaderDependencyStatus.MALFORMED)
    if (directive.operandKind == "quote") {
        val local = normalizeQuotedLocalTarget(currentArchivePath, spelling)
        if (local != null && local in regularPaths) {
            return result(SourceHeaderDependencyStatus.RESOLVED_LOCAL, listOf(local))
        }
    }
    val candidateKey = canonicalCandidateKey(spelling)
        ?: return result(SourceHeaderDependencyStatus.UNRESOLVED_ARCHIVE)
    val candidates = candidateIndex[candidateKey].orEmpty()
    if (candidates.size > maximumCandidatesPerDirective) {
        dependencyFailure("referenced dependency candidate set exceeds its per-directive bound: $candidateKey")
    }
    return when (candidates.size) {
        0 -> result(SourceHeaderDependencyStatus.UNRESOLVED_ARCHIVE)
        1 -> result(SourceHeaderDependencyStatus.UNIQUE_ARCHIVE_CANDIDATE, candidates)
        else -> result(SourceHeaderDependencyStatus.AMBIGUOUS_ARCHIVE_CANDIDATE, candidates)
    }
}

private class SourceHeaderDirectiveParser(
    private val sourcePath: String,
    private val maximumLogicalLineBytes: Int,
    private val maximumDirectives: Long,
) {
    private val physical = ByteArrayOutputStream()
    private val logical = ByteArrayOutputStream()
    private val directives = arrayListOf<SourceHeaderDependencyDirective>()
    private val conditionals = arrayListOf<ConditionalFrame>()
    private var physicalLine = 1L
    private var logicalStartLine = 1L
    private var ended = false
    private var finalized = false
    private var structureBalanced = true
    private var inBlockComment = false
    private var rawStringTerminator: String? = null

    fun accept(bytes: ByteArray, length: Int, endOfEntry: Boolean) {
        if (ended || finalized) dependencyFailure("dependency parser received bytes after end of file: $sourcePath")
        if (length !in 0..bytes.size) dependencyFailure("dependency parser received an invalid chunk")
        for (index in 0 until length) {
            val value = bytes[index].toInt() and 0xff
            if (value == 0) dependencyFailure("dependency source contains NUL: $sourcePath")
            if (value == '\n'.code) {
                finishPhysicalLine()
            } else {
                if (physical.size() >= maximumLogicalLineBytes) {
                    dependencyFailure("dependency source logical line exceeds its byte bound: $sourcePath")
                }
                physical.write(value)
            }
        }
        if (endOfEntry) {
            if (physical.size() != 0 || logical.size() != 0) finishPhysicalLine(endOfFile = true)
            ended = true
        }
    }

    fun finish(archivePath: String, size: Long): ParsedArchiveDependencyFile {
        if (!ended || finalized) dependencyFailure("dependency parser did not finish exactly once: $sourcePath")
        finalized = true
        if (conditionals.isNotEmpty() || inBlockComment || rawStringTerminator != null) structureBalanced = false
        return ParsedArchiveDependencyFile(
            archivePath = archivePath,
            sourcePath = sourcePath,
            bytes = size,
            structureBalanced = structureBalanced,
            directives = Collections.unmodifiableList(ArrayList(directives)),
        )
    }

    private fun finishPhysicalLine(endOfFile: Boolean = false) {
        var bytes = physical.toByteArray()
        physical.reset()
        if (bytes.lastOrNull() == '\r'.code.toByte()) bytes = bytes.copyOf(bytes.size - 1)
        val continued = bytes.lastOrNull() == '\\'.code.toByte()
        val payloadLength = if (continued) bytes.size - 1 else bytes.size
        if (logical.size() == 0) logicalStartLine = physicalLine
        if (logical.size().toLong() + payloadLength.toLong() > maximumLogicalLineBytes.toLong()) {
            dependencyFailure("dependency source logical line exceeds its byte bound: $sourcePath")
        }
        logical.write(bytes, 0, payloadLength)
        physicalLine = incrementDependency(physicalLine, "source physical line")
        if (continued) {
            if (endOfFile) dependencyFailure("dependency source ends in a line continuation: $sourcePath")
            return
        }
        parseLogicalLine(logical.toByteArray(), logicalStartLine)
        logical.reset()
    }

    private fun parseLogicalLine(bytes: ByteArray, line: Long) {
        val text = bytes.toString(StandardCharsets.ISO_8859_1)
        val visible = stripCommentsAndRawStrings(text)
        var cursor = skipDirectiveWhitespace(visible, 0)
        if (cursor >= visible.length || visible[cursor] != '#') return
        cursor = skipDirectiveWhitespace(visible, cursor + 1)
        val start = cursor
        while (cursor < visible.length && (visible[cursor] == '_' || visible[cursor].isLetterOrDigit())) cursor++
        if (cursor == start) return
        val name = visible.substring(start, cursor)
        val operand = visible.substring(cursor).trim()
        when (name) {
            "if", "ifdef", "ifndef" -> conditionals += ConditionalFrame()
            "elif", "elifdef", "elifndef" -> {
                if (conditionals.isEmpty() || conditionals.last().seenElse) structureBalanced = false
            }
            "else" -> {
                if (conditionals.isEmpty() || conditionals.last().seenElse) {
                    structureBalanced = false
                } else {
                    conditionals.last().seenElse = true
                }
            }
            "endif" -> {
                if (conditionals.isEmpty()) structureBalanced = false else conditionals.removeLast()
            }
            "include", "include_next", "import" -> addIncludeDirective(
                line,
                name,
                operand,
                conditionals.isNotEmpty(),
            )
        }
    }

    private fun addIncludeDirective(line: Long, name: String, operand: String, conditional: Boolean) {
        if (directives.size.toLong() >= maximumDirectives) {
            dependencyFailure("dependency directives exceed their count bound")
        }
        val parsed = parseIncludeOperand(operand)
        directives += SourceHeaderDependencyDirective(
            line = line,
            directive = name,
            operandKind = parsed.first,
            spelling = parsed.second,
            structurallyConditional = conditional,
        )
    }

    private fun stripCommentsAndRawStrings(input: String): String {
        val result = StringBuilder(input.length)
        var cursor = 0
        while (cursor < input.length) {
            val rawEnd = rawStringTerminator
            if (rawEnd != null) {
                val end = input.indexOf(rawEnd, cursor)
                if (end < 0) {
                    repeat(input.length - cursor) { result.append(' ') }
                    break
                }
                repeat(end + rawEnd.length - cursor) { result.append(' ') }
                cursor = end + rawEnd.length
                rawStringTerminator = null
                continue
            }
            if (inBlockComment) {
                val end = input.indexOf("*/", cursor)
                if (end < 0) {
                    repeat(input.length - cursor) { result.append(' ') }
                    break
                }
                repeat(end + 2 - cursor) { result.append(' ') }
                cursor = end + 2
                inBlockComment = false
                continue
            }
            if (input.startsWith("//", cursor)) {
                repeat(input.length - cursor) { result.append(' ') }
                break
            }
            if (input.startsWith("/*", cursor)) {
                result.append("  ")
                cursor += 2
                inBlockComment = true
                continue
            }
            val raw = rawStringOpening(input, cursor)
            if (raw != null) {
                repeat(raw.first - cursor) { result.append(' ') }
                cursor = raw.first
                rawStringTerminator = raw.second
                continue
            }
            val current = input[cursor]
            if (current == '"' || current == '\'') {
                val quote = current
                result.append(current)
                cursor++
                var escaped = false
                while (cursor < input.length) {
                    val character = input[cursor]
                    result.append(character)
                    cursor++
                    if (escaped) {
                        escaped = false
                    } else if (character == '\\') {
                        escaped = true
                    } else if (character == quote) {
                        break
                    }
                }
                continue
            }
            result.append(current)
            cursor++
        }
        return result.toString()
    }

    private data class ConditionalFrame(var seenElse: Boolean = false)
}

private fun rawStringOpening(input: String, offset: Int): Pair<Int, String>? {
    if (!input.startsWith("R\"", offset)) return null
    val delimiterStart = offset + 2
    val open = input.indexOf('(', delimiterStart)
    if (open < 0 || open - delimiterStart > 16) return null
    val delimiter = input.substring(delimiterStart, open)
    if (delimiter.any { it.isWhitespace() || it == '\\' || it == ')' }) return null
    return (open + 1) to ")$delimiter\""
}

private fun parseIncludeOperand(operand: String): Pair<String, String?> {
    if (operand.isEmpty()) return "malformed" to null
    val opener = operand.first()
    val closer = when (opener) {
        '"' -> '"'
        '<' -> '>'
        else -> return "macro" to operand
    }
    val close = operand.indexOf(closer, 1)
    if (close < 0 || close == 1 || operand.substring(close + 1).isNotBlank()) {
        return "malformed" to null
    }
    return (if (opener == '"') "quote" else "angle") to operand.substring(1, close)
}

private fun skipDirectiveWhitespace(value: String, start: Int): Int {
    var cursor = start
    while (cursor < value.length && value[cursor] in DIRECTIVE_WHITESPACE) cursor++
    return cursor
}

private data class DependencyProjection(
    val document: JsonObject,
    val directiveCount: Long,
    val resolvedLocalReferenceCount: Long,
)

private fun buildDependencyProjection(
    registry: AuthenticatedFullTreePlanningRegistry,
    planningOracle: JsonObject,
    archive: DependencyArchiveEvidence,
    resolvedFiles: Map<String, ResolvedArchiveDependencyFile>,
    archiveSummary: decompengine.oracle.provenance.BoundedTarXzSummary,
    archiveRoot: String,
    archiveCommit: String,
    archiveBytes: Long,
    archiveSha256: String,
    limits: FullTreeSourceHeaderDependencyLimits,
): DependencyProjection {
    val globalCounts = DependencyCounts()
    val allDirectiveCommitment = DependencyDirectiveCommitment("all-parsed-files", "all-directives")
    val allFileFactsCommitment = DependencyStringCommitment("all-parsed-file-facts")
    val factsByArchivePath = TreeMap<String, DependencyFacts>(FULL_TREE_CODE_POINT_ORDER)
    resolvedFiles.forEach { (path, file) ->
        val facts = dependencyFacts(file)
        factsByArchivePath[path] = facts
        globalCounts.add(facts.counts)
        file.resolved.forEach { allDirectiveCommitment.add(file.parsed.sourcePath, it) }
        allFileFactsCommitment.add(file.parsed.sourcePath)
        allFileFactsCommitment.add(file.parsed.bytes.toString())
        allFileFactsCommitment.add(if (file.parsed.structureBalanced) "balanced" else "unbalanced")
        allFileFactsCommitment.add(facts.counts.framedSummary())
        allFileFactsCommitment.add(facts.allDirectivesSha256)
    }
    if (globalCounts.total != archive.directiveCount) {
        dependencyFailure("dependency directive population differs from the streamed archive count")
    }

    val directModuleConsumers = TreeMap<String, MutableSet<String>>(FULL_TREE_CODE_POINT_ORDER)
    val directSourceOnlyConsumers = TreeMap<String, MutableSet<String>>(FULL_TREE_CODE_POINT_ORDER)
    val modules = registry.sourceModules.map { module ->
        val facts = if (module.sourceKind == "handwritten") {
            factsByArchivePath[sourceToArchivePath(module.sourcePath)]
                ?: dependencyFailure("handwritten module has no parsed dependency facts")
        } else {
            null
        }
        facts?.resolvedLocalFiles?.forEach { target ->
            directModuleConsumers.computeIfAbsent(target) { TreeSet(FULL_TREE_CODE_POINT_ORDER) }.add(module.moduleId)
        }
        JsonObject(
            mapOf(
                "dependencyFacts" to (facts?.document() ?: JsonNull),
                "moduleId" to JsonPrimitive(module.moduleId),
                "ownerUnitId" to JsonPrimitive(module.unitId),
                "shardId" to JsonPrimitive(module.shardId),
                "sourceKind" to JsonPrimitive(module.sourceKind),
                "sourcePath" to JsonPrimitive(module.sourcePath),
                "sourceStatus" to JsonPrimitive(
                    if (facts == null) "unavailable-generated-source" else "authenticated-archive-parsed",
                ),
            ),
        )
    }
    val sourceOnly = registry.sourceOnlyUnits.map { unit ->
        val facts = factsByArchivePath[sourceToArchivePath(unit.sourcePath)]
            ?: dependencyFailure("source-only unit has no parsed dependency facts")
        facts.resolvedLocalFiles.forEach { target ->
            directSourceOnlyConsumers.computeIfAbsent(target) { TreeSet(FULL_TREE_CODE_POINT_ORDER) }.add(unit.sourcePath)
        }
        JsonObject(
            mapOf(
                "dependencyFacts" to facts.document(),
                "ownershipStatus" to JsonPrimitive("excluded-non-owning"),
                "reasonCode" to JsonPrimitive(unit.reasonCode),
                "shardId" to JsonPrimitive(unit.shardId),
                "sourcePath" to JsonPrimitive(unit.sourcePath),
                "sourceStatus" to JsonPrimitive("authenticated-archive-parsed"),
            ),
        )
    }

    val dependencyFiles = resolvedFiles.values.asSequence()
        .filter { isDependencyPayloadPath(it.parsed.archivePath) }
        .filter { file ->
            file.resolved.isNotEmpty() || archiveToSourcePath(file.parsed.archivePath) in directModuleConsumers ||
                archiveToSourcePath(file.parsed.archivePath) in directSourceOnlyConsumers
        }
        .map { file ->
            JsonObject(
                mapOf(
                    "dependencyFacts" to factsByArchivePath.getValue(file.parsed.archivePath).document(),
                    "ownershipStatus" to JsonPrimitive("unassigned-header-planning-evidence"),
                    "sourcePath" to JsonPrimitive(file.parsed.sourcePath),
                ),
            )
        }
        .toList()
    val sharedHeaders = directModuleConsumers.entries.asSequence()
        .filter { (path, consumers) -> isDependencyPayloadPath(path.removePrefix("source/")) && consumers.size > 1 }
        .map { (path, consumers) ->
            JsonObject(
                mapOf(
                    "consumerBasis" to JsonPrimitive("direct-translation-unit-resolved-local-reference-only"),
                    "directModuleIds" to JsonArray(consumers.map(::JsonPrimitive)),
                    "directSourceOnlyPaths" to JsonArray(
                        directSourceOnlyConsumers[path].orEmpty().map(::JsonPrimitive),
                    ),
                    "ownershipStatus" to JsonPrimitive("unassigned-header-planning-evidence"),
                    "sourcePath" to JsonPrimitive(path),
                ),
            )
        }
        .toList()

    val outputRecords = listOf(modules.size, sourceOnly.size, dependencyFiles.size, sharedHeaders.size)
        .fold(0L) { total, count -> addDependencyCount(total, count.toLong(), "dependency output record") }
    if (outputRecords > limits.maximumOutputRecords || outputRecords > DEPENDENCY_MAXIMUM_OUTPUT_RECORDS) {
        dependencyFailure("dependency assessment exceeds its output-record bound")
    }
    val workUnits = listOf(
        archive.archiveMembers.toLong(),
        archive.regularPaths.size.toLong(),
        archive.parsedFiles.size.toLong(),
        archive.directiveCount,
        outputRecords,
    ).fold(0L) { total, count -> addDependencyCount(total, count, "dependency work-unit") }
    if (workUnits > limits.maximumWorkUnits || workUnits > DEPENDENCY_MAXIMUM_WORK_UNITS) {
        dependencyFailure("dependency assessment exceeds its work-unit bound")
    }

    val resolvedLocalFileEdges = factsByArchivePath.values.sumOf { it.resolvedLocalFiles.size.toLong() }
    val uniqueCandidateFileReferences = factsByArchivePath.values.sumOf {
        it.uniqueArchiveCandidateFiles.size.toLong()
    }
    val withoutHash = JsonObject(
        mapOf(
            "archive" to JsonObject(
                mapOf(
                    "commit" to JsonPrimitive(archiveCommit),
                    "compressedBytes" to JsonPrimitive(archiveBytes),
                    "expandedBytes" to JsonPrimitive(archiveSummary.expandedBytes),
                    "memberCount" to JsonPrimitive(archiveSummary.memberCount),
                    "regularFileCount" to JsonPrimitive(archiveSummary.regularFileCount),
                    "relevantRegularPathCommitmentSha256" to
                        JsonPrimitive(archive.relevantRegularPathCommitmentSha256),
                    "root" to JsonPrimitive(archiveRoot),
                    "sha256" to JsonPrimitive(archiveSha256),
                ),
            ),
            "authority" to JsonObject(
                mapOf(
                    "cleanCompilationProven" to JsonPrimitive(false),
                    "purpose" to JsonPrimitive("source-header-dependency-planning-evidence"),
                    "releaseEligible" to JsonPrimitive(false),
                    "status" to JsonPrimitive("planning-only-non-authoritative"),
                ),
            ),
            "bounds" to JsonObject(
                mapOf(
                    "maximumCandidatesPerDirective" to JsonPrimitive(DEPENDENCY_MAXIMUM_CANDIDATES_PER_DIRECTIVE),
                    "maximumDirectives" to JsonPrimitive(DEPENDENCY_MAXIMUM_DIRECTIVES),
                    "maximumIndexedRegularFiles" to JsonPrimitive(DEPENDENCY_MAXIMUM_INDEXED_REGULAR_FILES),
                    "maximumLogicalLineBytes" to JsonPrimitive(DEPENDENCY_MAXIMUM_LOGICAL_LINE_BYTES),
                    "maximumOutputRecords" to JsonPrimitive(DEPENDENCY_MAXIMUM_OUTPUT_RECORDS),
                    "maximumParsedBytes" to JsonPrimitive(DEPENDENCY_MAXIMUM_PARSED_BYTES),
                    "maximumParsedFileBytes" to JsonPrimitive(DEPENDENCY_MAXIMUM_PARSED_FILE_BYTES),
                    "maximumParsedFiles" to JsonPrimitive(DEPENDENCY_MAXIMUM_PARSED_FILES),
                    "maximumSerializedBytes" to JsonPrimitive(DEPENDENCY_MAXIMUM_SERIALIZED_BYTES),
                    "maximumWorkUnits" to JsonPrimitive(DEPENDENCY_MAXIMUM_WORK_UNITS),
                ),
            ),
            "commitments" to JsonObject(
                mapOf(
                    "allDirectivesSha256" to JsonPrimitive(allDirectiveCommitment.finish()),
                    "allParsedFileFactsSha256" to JsonPrimitive(allFileFactsCommitment.finish()),
                ),
            ),
            "counts" to JsonObject(
                mapOf(
                    "ambiguousArchiveCandidateDirectives" to JsonPrimitive(globalCounts.ambiguousArchiveCandidate),
                    "conditionalDirectives" to JsonPrimitive(globalCounts.conditional),
                    "dependencyFilesWithFacts" to JsonPrimitive(dependencyFiles.size),
                    "directives" to JsonPrimitive(globalCounts.total),
                    "generatedSourceModulesUnavailable" to JsonPrimitive(
                        registry.sourceModules.count { it.sourceKind == "generated" },
                    ),
                    "handwrittenSourceModulesParsed" to JsonPrimitive(
                        registry.sourceModules.count { it.sourceKind == "handwritten" },
                    ),
                    "indexedRelevantRegularFiles" to JsonPrimitive(archive.regularPaths.size),
                    "macroDirectives" to JsonPrimitive(globalCounts.macro),
                    "malformedDirectives" to JsonPrimitive(globalCounts.malformed),
                    "nonstandardDirectives" to JsonPrimitive(globalCounts.nonstandard),
                    "parsedBytes" to JsonPrimitive(archive.parsedBytes),
                    "parsedFiles" to JsonPrimitive(archive.parsedFiles.size),
                    "resolvedLocalDirectives" to JsonPrimitive(globalCounts.resolvedLocal),
                    "resolvedLocalFileEdges" to JsonPrimitive(resolvedLocalFileEdges),
                    "sharedHeaders" to JsonPrimitive(sharedHeaders.size),
                    "sourceModules" to JsonPrimitive(registry.sourceModules.size),
                    "sourceOnlyUnits" to JsonPrimitive(registry.sourceOnlyUnits.size),
                    "uniqueArchiveCandidateDirectives" to JsonPrimitive(globalCounts.uniqueArchiveCandidate),
                    "uniqueArchiveCandidateFileReferences" to JsonPrimitive(uniqueCandidateFileReferences),
                    "unresolvedArchiveDirectives" to JsonPrimitive(globalCounts.unresolvedArchive),
                    "workUnits" to JsonPrimitive(workUnits),
                ),
            ),
            "dependencyFiles" to JsonArray(dependencyFiles),
            "moduleGraph" to JsonObject(
                mapOf(
                    "cleanCompilationProven" to JsonPrimitive(false),
                    "edgePopulationKnown" to JsonPrimitive(false),
                    "status" to JsonPrimitive(
                        "withheld-until-authenticated-compiler-resolution-and-header-ownership",
                    ),
                ),
            ),
            "modules" to JsonArray(modules),
            "oracle" to JsonObject(
                mapOf(
                    "artifactManifestSha256" to planningOracle.getValue("artifactManifestSha256"),
                    "buildRecordSha256" to planningOracle.getValue("buildRecordSha256"),
                    "configurationSha256" to JsonPrimitive(FullTreeSourceHeaderDependencies.configurationSha256),
                    "id" to planningOracle.getValue("id"),
                    "inventoryArtifactSha256" to planningOracle.getValue("inventoryArtifactSha256"),
                    "inventoryIndexSha256" to planningOracle.getValue("inventoryIndexSha256"),
                    "planningInventoryArtifactSha256" to JsonPrimitive(registry.artifactSha256),
                    "planningInventoryConfigurationSha256" to JsonPrimitive(registry.configurationSha256),
                    "planningInventoryReportSha256" to JsonPrimitive(registry.reportSha256),
                    "scopeSha256" to planningOracle.getValue("scopeSha256"),
                    "sourceArchiveSha256" to JsonPrimitive(archiveSha256),
                    "sourceInventoryArtifactSha256" to planningOracle.getValue("sourceInventoryArtifactSha256"),
                    "sourceInventoryReportSha256" to planningOracle.getValue("sourceInventoryReportSha256"),
                    "sourceLockSha256" to planningOracle.getValue("sourceLockSha256"),
                ),
            ),
            "resolutionPolicy" to JsonObject(
                mapOf(
                    "conditionalIncludes" to JsonPrimitive("recorded-as-non-edge-without-expression-evaluation"),
                    "headerOwnership" to JsonPrimitive("unassigned"),
                    "localReference" to JsonPrimitive(
                        "unconditional-literal-quoted-relative-to-including-directory-authenticated-regular-file",
                    ),
                    "nonLocalLiterals" to JsonPrimitive(
                        "archive-candidates-only-without-compiler-search-order",
                    ),
                    "sourceOnlyOwnership" to JsonPrimitive("forbidden"),
                    "transitiveResolution" to JsonPrimitive("not-performed"),
                ),
            ),
            "schemaVersion" to JsonPrimitive(1),
            "sharedHeaders" to JsonArray(sharedHeaders),
            "sourceOnly" to JsonArray(sourceOnly),
        ),
    )
    val reportSha256 = OracleArtifacts.sha256(canonicalDependencyBytes(withoutHash, limits.maximumSerializedBytes))
    val document = JsonObject(withoutHash + ("reportSha256" to JsonPrimitive(reportSha256)))
    return DependencyProjection(document, globalCounts.total, globalCounts.resolvedLocal)
}

private fun dependencyFacts(file: ResolvedArchiveDependencyFile): DependencyFacts {
    val counts = DependencyCounts()
    val resolvedLocal = TreeSet(FULL_TREE_CODE_POINT_ORDER)
    val uniqueCandidates = TreeSet(FULL_TREE_CODE_POINT_ORDER)
    val all = DependencyDirectiveCommitment(file.parsed.sourcePath, "all")
    val resolved = DependencyDirectiveCommitment(file.parsed.sourcePath, "resolved-local")
    val candidates = DependencyDirectiveCommitment(file.parsed.sourcePath, "archive-candidates")
    val nonEdges = DependencyDirectiveCommitment(file.parsed.sourcePath, "non-edges")
    file.resolved.forEach { directive ->
        counts.add(directive.status)
        all.add(file.parsed.sourcePath, directive)
        when (directive.status) {
            SourceHeaderDependencyStatus.RESOLVED_LOCAL -> {
                resolved.add(file.parsed.sourcePath, directive)
                resolvedLocal += directive.targets
            }
            SourceHeaderDependencyStatus.UNIQUE_ARCHIVE_CANDIDATE,
            SourceHeaderDependencyStatus.AMBIGUOUS_ARCHIVE_CANDIDATE,
            -> {
                candidates.add(file.parsed.sourcePath, directive)
                if (directive.status == SourceHeaderDependencyStatus.UNIQUE_ARCHIVE_CANDIDATE) {
                    uniqueCandidates += directive.targets
                }
            }
            else -> nonEdges.add(file.parsed.sourcePath, directive)
        }
    }
    return DependencyFacts(
        structureBalanced = file.parsed.structureBalanced,
        counts = counts,
        resolvedLocalFiles = resolvedLocal.toList(),
        uniqueArchiveCandidateFiles = uniqueCandidates.toList(),
        allDirectivesSha256 = all.finish(),
        resolvedLocalDirectivesSha256 = resolved.finish(),
        archiveCandidateDirectivesSha256 = candidates.finish(),
        nonEdgeDirectivesSha256 = nonEdges.finish(),
    )
}

private data class DependencyFacts(
    val structureBalanced: Boolean,
    val counts: DependencyCounts,
    val resolvedLocalFiles: List<String>,
    val uniqueArchiveCandidateFiles: List<String>,
    val allDirectivesSha256: String,
    val resolvedLocalDirectivesSha256: String,
    val archiveCandidateDirectivesSha256: String,
    val nonEdgeDirectivesSha256: String,
) {
    fun document(): JsonObject = JsonObject(
        mapOf(
            "commitments" to JsonObject(
                mapOf(
                    "allDirectivesSha256" to JsonPrimitive(allDirectivesSha256),
                    "archiveCandidateDirectivesSha256" to JsonPrimitive(archiveCandidateDirectivesSha256),
                    "nonEdgeDirectivesSha256" to JsonPrimitive(nonEdgeDirectivesSha256),
                    "resolvedLocalDirectivesSha256" to JsonPrimitive(resolvedLocalDirectivesSha256),
                ),
            ),
            "conditionalStructure" to JsonPrimitive(
                if (structureBalanced) "balanced" else "unbalanced-all-directives-withheld",
            ),
            "counts" to counts.document(),
            "resolvedLocalFiles" to JsonArray(resolvedLocalFiles.map(::JsonPrimitive)),
            "uniqueArchiveCandidateFiles" to JsonArray(uniqueArchiveCandidateFiles.map(::JsonPrimitive)),
        ),
    )
}

private class DependencyCounts {
    var total = 0L
        private set
    var resolvedLocal = 0L
        private set
    var uniqueArchiveCandidate = 0L
        private set
    var ambiguousArchiveCandidate = 0L
        private set
    var unresolvedArchive = 0L
        private set
    var conditional = 0L
        private set
    var macro = 0L
        private set
    var nonstandard = 0L
        private set
    var malformed = 0L
        private set

    fun add(status: SourceHeaderDependencyStatus) {
        total = incrementDependency(total, "dependency directive")
        when (status) {
            SourceHeaderDependencyStatus.RESOLVED_LOCAL -> resolvedLocal = incrementDependency(resolvedLocal, "resolved local directive")
            SourceHeaderDependencyStatus.UNIQUE_ARCHIVE_CANDIDATE -> uniqueArchiveCandidate = incrementDependency(uniqueArchiveCandidate, "unique candidate directive")
            SourceHeaderDependencyStatus.AMBIGUOUS_ARCHIVE_CANDIDATE -> ambiguousArchiveCandidate = incrementDependency(ambiguousArchiveCandidate, "ambiguous candidate directive")
            SourceHeaderDependencyStatus.UNRESOLVED_ARCHIVE -> unresolvedArchive = incrementDependency(unresolvedArchive, "unresolved directive")
            SourceHeaderDependencyStatus.CONDITIONAL -> conditional = incrementDependency(conditional, "conditional directive")
            SourceHeaderDependencyStatus.MACRO -> macro = incrementDependency(macro, "macro directive")
            SourceHeaderDependencyStatus.NONSTANDARD -> nonstandard = incrementDependency(nonstandard, "nonstandard directive")
            SourceHeaderDependencyStatus.MALFORMED -> malformed = incrementDependency(malformed, "malformed directive")
        }
    }

    fun add(other: DependencyCounts) {
        total = addDependencyCount(total, other.total, "dependency directive")
        resolvedLocal = addDependencyCount(resolvedLocal, other.resolvedLocal, "resolved local directive")
        uniqueArchiveCandidate = addDependencyCount(uniqueArchiveCandidate, other.uniqueArchiveCandidate, "unique candidate directive")
        ambiguousArchiveCandidate = addDependencyCount(ambiguousArchiveCandidate, other.ambiguousArchiveCandidate, "ambiguous candidate directive")
        unresolvedArchive = addDependencyCount(unresolvedArchive, other.unresolvedArchive, "unresolved directive")
        conditional = addDependencyCount(conditional, other.conditional, "conditional directive")
        macro = addDependencyCount(macro, other.macro, "macro directive")
        nonstandard = addDependencyCount(nonstandard, other.nonstandard, "nonstandard directive")
        malformed = addDependencyCount(malformed, other.malformed, "malformed directive")
        if (total != resolvedLocal + uniqueArchiveCandidate + ambiguousArchiveCandidate + unresolvedArchive +
            conditional + macro + nonstandard + malformed
        ) {
            dependencyFailure("dependency directive populations do not reconcile")
        }
    }

    fun document(): JsonObject = JsonObject(
        mapOf(
            "ambiguousArchiveCandidate" to JsonPrimitive(ambiguousArchiveCandidate),
            "conditional" to JsonPrimitive(conditional),
            "macro" to JsonPrimitive(macro),
            "malformed" to JsonPrimitive(malformed),
            "nonstandard" to JsonPrimitive(nonstandard),
            "resolvedLocal" to JsonPrimitive(resolvedLocal),
            "total" to JsonPrimitive(total),
            "uniqueArchiveCandidate" to JsonPrimitive(uniqueArchiveCandidate),
            "unresolvedArchive" to JsonPrimitive(unresolvedArchive),
        ),
    )

    fun framedSummary(): String = listOf(
        total,
        resolvedLocal,
        uniqueArchiveCandidate,
        ambiguousArchiveCandidate,
        unresolvedArchive,
        conditional,
        macro,
        nonstandard,
        malformed,
    ).joinToString(":")
}

private class DependencyDirectiveCommitment(owner: String, population: String) {
    private val commitment = DependencyStringCommitment("directive", owner, population)

    fun add(sourcePath: String, directive: ResolvedSourceHeaderDependencyDirective) {
        commitment.add(sourcePath)
        commitment.add(directive.raw.line.toString())
        commitment.add(directive.raw.directive)
        commitment.add(directive.raw.operandKind)
        commitment.add(directive.raw.spelling.orEmpty())
        commitment.add(if (directive.raw.structurallyConditional) "conditional" else "top-level")
        commitment.add(directive.status.wireName)
        commitment.add(directive.targets.size.toString())
        directive.targets.forEach(commitment::add)
    }

    fun finish(): String = commitment.finish()
}

private class DependencyStringCommitment(vararg domain: String) {
    private val digest = MessageDigest.getInstance("SHA-256")
    private var finished: String? = null

    init {
        addFramed(DEPENDENCY_COMMITMENT_DOMAIN)
        domain.forEach(::addFramed)
    }

    fun add(value: String) {
        if (finished != null) dependencyFailure("dependency commitment is already finalized")
        addFramed(value)
    }

    fun finish(): String = finished ?: digest.digest().hexDependency().also { finished = it }

    private fun addFramed(value: String) {
        val bytes = value.toByteArray(StandardCharsets.UTF_8)
        if (bytes.size > 1024 * 1024) dependencyFailure("dependency commitment component is oversized")
        digest.update(ByteBuffer.allocate(Int.SIZE_BYTES).putInt(bytes.size).array())
        digest.update(bytes)
    }
}

private fun commitStrings(domain: String, population: String, values: Iterable<String>): String {
    val commitment = DependencyStringCommitment(domain, population)
    values.forEach(commitment::add)
    return commitment.finish()
}

private fun dependencyCandidateKeys(path: String): Set<String> {
    val keys = TreeSet(FULL_TREE_CODE_POINT_ORDER)
    if (!isDependencyPayloadPath(path)) return keys
    canonicalCandidateKey(path)?.let(keys::add)
    val includeMarker = "/include/"
    val marker = path.indexOf(includeMarker)
    if (marker >= 0) canonicalCandidateKey(path.substring(marker + includeMarker.length))?.let(keys::add)
    if (path.startsWith("include/")) canonicalCandidateKey(path.removePrefix("include/"))?.let(keys::add)
    return keys
}

private fun canonicalCandidateKey(spelling: String): String? {
    if (!isSafeIncludeSpelling(spelling)) return null
    val parts = spelling.split('/')
    if (parts.any { it.isEmpty() || it == "." || it == ".." }) return null
    return parts.joinToString("/")
}

private fun normalizeQuotedLocalTarget(current: String, spelling: String): String? {
    if (!isSafeIncludeSpelling(spelling)) return null
    val parts = current.substringBeforeLast('/', "").split('/').filter(String::isNotEmpty).toMutableList()
    spelling.split('/').forEach { component ->
        when (component) {
            "" -> return null
            "." -> Unit
            ".." -> if (parts.isEmpty()) return null else parts.removeLast()
            else -> parts += component
        }
    }
    if (parts.isEmpty()) return null
    return parts.joinToString("/")
}

private fun isSafeIncludeSpelling(value: String): Boolean =
    value.isNotEmpty() && !value.startsWith('/') && '\\' !in value && "//" !in value &&
        value.all { it.code in 0x20..0x7e }

private fun sourceToArchivePath(sourcePath: String): String {
    if (!sourcePath.startsWith("source/")) dependencyFailure("archive-backed source path lacks the source/ prefix")
    val relative = sourcePath.removePrefix("source/")
    if (!isCanonicalDependencyPath(relative)) dependencyFailure("archive-backed source path is not canonical")
    return relative
}

private fun archiveToSourcePath(archivePath: String): String {
    if (!isCanonicalDependencyPath(archivePath)) dependencyFailure("archive dependency path is not canonical")
    return "source/$archivePath"
}

private fun requireGeneratedSourcePath(path: String) {
    val relative = path.removePrefix("generated/")
    if (!path.startsWith("generated/") || !isCanonicalDependencyPath(relative)) {
        dependencyFailure("generated source path is not canonical")
    }
}

private fun isCanonicalDependencyPath(path: String): Boolean =
    path.isNotEmpty() && !path.startsWith('/') && '\\' !in path && path.length <= 4096 &&
        path.all { it.code in 0x20..0x7e } &&
        path.split('/').all { it.isNotEmpty() && it != "." && it != ".." }

private fun isWithinEnabledRoots(path: String, enabledRoots: Set<String>): Boolean =
    path.substringBefore('/') in enabledRoots

private fun isDependencyPayloadPath(path: String): Boolean =
    DEPENDENCY_SUFFIXES.any(path::endsWith)

private fun dependencyArchiveLimits(limits: FullTreeSourceHeaderDependencyLimits): BoundedTarXzLimits {
    val control = limits.planning.control
    return BoundedTarXzLimits(
        maximumCompressedBytes = control.maximumSourceArchiveBytes,
        maximumExpandedBytes = control.maximumExpandedArchiveBytes,
        maximumDecoderMemoryKiB = control.maximumXzDecoderMemoryKiB,
        maximumMembers = control.maximumArchiveMembers,
        maximumMetadataBytes = control.maximumArchiveMetadataBytes,
        maximumEntryBytes = control.maximumArchiveEntryBytes,
        maximumPathBytes = control.maximumArchivePathBytes,
        maximumComponentBytes = control.maximumArchiveComponentBytes,
        maximumLinkBytes = control.maximumArchiveLinkBytes,
        maximumIndexBytes = control.maximumArchiveIndexBytes,
        maximumSelectedBytes = 0,
    )
}

private fun canonicalDependencyBytes(document: JsonObject, maximumBytes: Int): ByteArray = try {
    OracleJson.canonicalBytes(
        document,
        StrictJsonLimits(
            maximumInputBytes = maximumBytes,
            maximumCanonicalBytes = maximumBytes,
            maximumDepth = 32,
            maximumNodes = 1_000_000,
            maximumStringBytes = 1024 * 1024,
            maximumTotalStringBytes = maximumBytes,
        ),
    )
} catch (failure: Exception) {
    throw FullTreeSourceHeaderDependencyException("dependency output exceeds canonical bounds", failure)
}

private fun validateDependencySchema(document: JsonObject) {
    try {
        OracleSchemas.validate(DEPENDENCY_SCHEMA, document)
    } catch (failure: Exception) {
        throw FullTreeSourceHeaderDependencyException("generated dependency output fails its schema", failure)
    }
}

private fun requireDistinctDependencyInputs(paths: DependencyPaths) {
    val normalized = paths.all().map { it.toAbsolutePath().normalize() }
    if (normalized.toSet().size != normalized.size) dependencyFailure("dependency input paths must be distinct")
    val identities = HashSet<Any>()
    normalized.forEach { path ->
        val attributes = try {
            Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
        } catch (failure: Exception) {
            throw FullTreeSourceHeaderDependencyException("dependency input is unavailable", failure)
        }
        if (!attributes.isRegularFile || attributes.isSymbolicLink || attributes.fileKey() == null) {
            dependencyFailure("dependency input is not an identified regular file")
        }
        if (!identities.add(attributes.fileKey())) dependencyFailure("dependency inputs contain a physical-file alias")
    }
}

private fun requireDependencyDigest(value: String, label: String) {
    if (!value.matches(DEPENDENCY_SHA256)) dependencyFailure("$label digest is invalid")
}

private fun addDependencyCount(left: Long, right: Long, label: String): Long = try {
    Math.addExact(left, right)
} catch (failure: ArithmeticException) {
    throw FullTreeSourceHeaderDependencyException("$label count overflows", failure)
}

private fun incrementDependency(value: Long, label: String): Long = addDependencyCount(value, 1L, label)

private fun dependencyFailure(message: String): Nothing = throw FullTreeSourceHeaderDependencyException(message)

private fun ByteArray.hexDependency(): String = joinToString("") { byte ->
    (byte.toInt() and 0xff).toString(16).padStart(2, '0')
}

private data class DependencyPaths(
    val sourceArchive: Path,
    val scope: Path,
    val sourceLock: Path,
    val artifactManifest: Path,
    val buildRecord: Path,
    val inventory: Path,
    val sourceInventory: Path,
    val planningInventory: Path,
) {
    fun all(): List<Path> = listOf(
        sourceArchive,
        scope,
        sourceLock,
        artifactManifest,
        buildRecord,
        inventory,
        sourceInventory,
        planningInventory,
    )
}

private data class DependencyAssessmentState(
    val reportSha256: String,
    val directiveCount: Long,
    val resolvedLocalReferenceCount: Long,
    val bytes: ByteArray,
)

private data class ParsedArchiveDependencyFile(
    val archivePath: String,
    val sourcePath: String,
    val bytes: Long,
    val structureBalanced: Boolean,
    val directives: List<SourceHeaderDependencyDirective>,
)

private data class ResolvedArchiveDependencyFile(
    val parsed: ParsedArchiveDependencyFile,
    val resolved: List<ResolvedSourceHeaderDependencyDirective>,
)

private data class DependencyArchiveEvidence(
    val regularPaths: Set<String>,
    val parsedFiles: Map<String, ParsedArchiveDependencyFile>,
    val parsedBytes: Long,
    val directiveCount: Long,
    val relevantRegularPathCommitmentSha256: String,
    val archiveMembers: Int,
)

private val DIRECTIVE_WHITESPACE = setOf(' ', '\t', '\r', '\u000c')
private val DEPENDENCY_SUFFIXES = listOf(".def", ".h", ".hh", ".hpp", ".hxx", ".inc")
private val DEPENDENCY_SHA256 = Regex("[0-9a-f]{64}")
private const val DEPENDENCY_SCHEMA = "full-tree-source-header-dependencies"
private const val DEPENDENCY_COMMITMENT_DOMAIN = "full-tree-source-header-dependencies-v1-length-framed-utf8"
internal const val DEPENDENCY_MAXIMUM_INDEXED_REGULAR_FILES = 200_000
internal const val DEPENDENCY_MAXIMUM_PARSED_FILES = 100_000
internal const val DEPENDENCY_MAXIMUM_PARSED_BYTES = 1024L * 1024L * 1024L
internal const val DEPENDENCY_MAXIMUM_PARSED_FILE_BYTES = 16L * 1024L * 1024L
internal const val DEPENDENCY_MAXIMUM_LOGICAL_LINE_BYTES = 256 * 1024
internal const val DEPENDENCY_MAXIMUM_DIRECTIVES = 1_000_000L
internal const val DEPENDENCY_MAXIMUM_CANDIDATES_PER_DIRECTIVE = 64
internal const val DEPENDENCY_MAXIMUM_OUTPUT_RECORDS = 100_000
internal const val DEPENDENCY_MAXIMUM_WORK_UNITS = 2_000_000L
internal const val DEPENDENCY_MAXIMUM_SERIALIZED_BYTES = 64 * 1024 * 1024
private val DEPENDENCY_POLICY = JsonObject(
    mapOf(
        "candidateResolution" to JsonPrimitive("exact-archive-path-or-public-include-spelling-without-search-order"),
        "conditionalIncludes" to JsonPrimitive("non-edge"),
        "dependencySuffixes" to JsonArray(DEPENDENCY_SUFFIXES.map(::JsonPrimitive)),
        "headerOwnership" to JsonPrimitive("unassigned"),
        "id" to JsonPrimitive(DEPENDENCY_SCHEMA),
        "localReference" to JsonPrimitive(
            "unconditional-literal-quoted-relative-to-including-directory-authenticated-regular-file",
        ),
        "maximumCandidatesPerDirective" to JsonPrimitive(DEPENDENCY_MAXIMUM_CANDIDATES_PER_DIRECTIVE),
        "maximumDirectives" to JsonPrimitive(DEPENDENCY_MAXIMUM_DIRECTIVES),
        "maximumIndexedRegularFiles" to JsonPrimitive(DEPENDENCY_MAXIMUM_INDEXED_REGULAR_FILES),
        "maximumLogicalLineBytes" to JsonPrimitive(DEPENDENCY_MAXIMUM_LOGICAL_LINE_BYTES),
        "maximumOutputRecords" to JsonPrimitive(DEPENDENCY_MAXIMUM_OUTPUT_RECORDS),
        "maximumParsedBytes" to JsonPrimitive(DEPENDENCY_MAXIMUM_PARSED_BYTES),
        "maximumParsedFileBytes" to JsonPrimitive(DEPENDENCY_MAXIMUM_PARSED_FILE_BYTES),
        "maximumParsedFiles" to JsonPrimitive(DEPENDENCY_MAXIMUM_PARSED_FILES),
        "maximumSerializedBytes" to JsonPrimitive(DEPENDENCY_MAXIMUM_SERIALIZED_BYTES),
        "maximumWorkUnits" to JsonPrimitive(DEPENDENCY_MAXIMUM_WORK_UNITS),
        "moduleGraph" to JsonPrimitive("withheld-without-compiler-resolution-and-header-ownership"),
        "sourceOnlyOwnership" to JsonPrimitive("forbidden"),
        "version" to JsonPrimitive(1),
    ),
)
