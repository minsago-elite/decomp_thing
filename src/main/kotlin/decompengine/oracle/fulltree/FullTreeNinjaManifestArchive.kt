package decompengine.oracle.fulltree

import decompengine.oracle.provenance.BoundedTarEntry
import decompengine.oracle.provenance.BoundedTarEntryKind
import decompengine.oracle.provenance.BoundedTarXzArchive
import decompengine.oracle.provenance.BoundedTarXzException
import decompengine.oracle.provenance.BoundedTarXzLimits
import decompengine.oracle.provenance.BoundedTarXzRegularFileVisitor
import decompengine.oracle.provenance.BoundedTarXzSource
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.nio.file.Path
import java.security.MessageDigest
import java.util.Collections
import java.util.TreeMap
import java.util.TreeSet

class FullTreeNinjaManifestArchiveException(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

/** Caller-lowerable ceilings beneath the immutable Ninja manifest-archive v1 policy. */
data class FullTreeNinjaManifestArchiveLimits(
    val maximumArchiveBytes: Long = NINJA_MANIFEST_MAXIMUM_ARCHIVE_BYTES,
    val maximumExpandedArchiveBytes: Long = NINJA_MANIFEST_MAXIMUM_EXPANDED_ARCHIVE_BYTES,
    val maximumXzDecoderMemoryKiB: Int = NINJA_MANIFEST_MAXIMUM_XZ_DECODER_MEMORY_KIB,
    val maximumArchiveMembers: Int = NINJA_MANIFEST_MAXIMUM_ARCHIVE_MEMBERS,
    val maximumArchiveIndexBytes: Long = NINJA_MANIFEST_MAXIMUM_ARCHIVE_INDEX_BYTES,
    val maximumManifestFiles: Int = NINJA_MANIFEST_MAXIMUM_FILES,
    val maximumManifestFileBytes: Int = NINJA_MANIFEST_MAXIMUM_FILE_BYTES,
    val maximumTotalManifestBytes: Long = NINJA_MANIFEST_MAXIMUM_TOTAL_FILE_BYTES,
    val maximumPhysicalLines: Int = NINJA_MANIFEST_MAXIMUM_PHYSICAL_LINES,
    val maximumLogicalLineBytes: Int = NINJA_MANIFEST_MAXIMUM_LOGICAL_LINE_BYTES,
    val maximumIncludeEdges: Int = NINJA_MANIFEST_MAXIMUM_INCLUDE_EDGES,
    val maximumRules: Int = NINJA_MANIFEST_MAXIMUM_RULES,
    val maximumGraphWorkUnits: Long = NINJA_MANIFEST_MAXIMUM_GRAPH_WORK_UNITS,
    val maximumPathBytes: Int = NINJA_MANIFEST_MAXIMUM_PATH_BYTES,
    val maximumPathComponentBytes: Int = NINJA_MANIFEST_MAXIMUM_PATH_COMPONENT_BYTES,
    val maximumRuleNameBytes: Int = NINJA_MANIFEST_MAXIMUM_RULE_NAME_BYTES,
) {
    init {
        require(maximumArchiveBytes in 1L..NINJA_MANIFEST_MAXIMUM_ARCHIVE_BYTES)
        require(maximumExpandedArchiveBytes in 1L..NINJA_MANIFEST_MAXIMUM_EXPANDED_ARCHIVE_BYTES)
        require(maximumXzDecoderMemoryKiB in 1..NINJA_MANIFEST_MAXIMUM_XZ_DECODER_MEMORY_KIB)
        require(maximumArchiveMembers in 1..NINJA_MANIFEST_MAXIMUM_ARCHIVE_MEMBERS)
        require(maximumArchiveIndexBytes in 1L..NINJA_MANIFEST_MAXIMUM_ARCHIVE_INDEX_BYTES)
        require(maximumManifestFiles in 1..NINJA_MANIFEST_MAXIMUM_FILES)
        require(maximumManifestFileBytes in 1..NINJA_MANIFEST_MAXIMUM_FILE_BYTES)
        require(maximumTotalManifestBytes in 1L..NINJA_MANIFEST_MAXIMUM_TOTAL_FILE_BYTES)
        require(maximumPhysicalLines in 1..NINJA_MANIFEST_MAXIMUM_PHYSICAL_LINES)
        require(maximumLogicalLineBytes in 1..NINJA_MANIFEST_MAXIMUM_LOGICAL_LINE_BYTES)
        require(maximumIncludeEdges in 1..NINJA_MANIFEST_MAXIMUM_INCLUDE_EDGES)
        require(maximumRules in 1..NINJA_MANIFEST_MAXIMUM_RULES)
        require(maximumGraphWorkUnits in 1L..NINJA_MANIFEST_MAXIMUM_GRAPH_WORK_UNITS)
        require(maximumPathBytes in 1..NINJA_MANIFEST_MAXIMUM_PATH_BYTES)
        require(maximumPathComponentBytes in 1..NINJA_MANIFEST_MAXIMUM_PATH_COMPONENT_BYTES)
        require(maximumRuleNameBytes in 1..NINJA_MANIFEST_MAXIMUM_RULE_NAME_BYTES)
        require(maximumManifestFileBytes.toLong() <= maximumTotalManifestBytes)
    }
}

/** Immutable identity for one regular manifest in the exact reachable closure. */
sealed interface FullTreeNinjaManifestFile {
    val path: String
    val bytes: Long
    val sha256: String
}

enum class FullTreeNinjaManifestEdgeKind {
    INCLUDE,
    SUBNINJA,
}

/** One literal top-level include or subninja edge, resolved from the build-root namespace. */
sealed interface FullTreeNinjaManifestEdge {
    val sourcePath: String
    val line: Int
    val kind: FullTreeNinjaManifestEdgeKind
    val targetPath: String
}

/** One unique literal top-level Ninja rule declaration. */
sealed interface FullTreeNinjaManifestRule {
    val sourcePath: String
    val line: Int
    val name: String
}

/**
 * Descriptor-authenticated, immutable syntax snapshot of an exact Ninja manifest closure.
 *
 * These identities authenticate only archive bytes, literal include topology, and literal rule
 * declarations. They retain no descriptor, process, invocation, environment, mount, execution,
 * build-graph, compiler, oracle, or release authority.
 */
sealed interface FullTreeNinjaManifestSnapshot {
    val archiveBytes: Long
    val archiveSha256: String
    val configurationSha256: String
    val reportSha256: String
    val archiveRoot: String
    val rootManifest: String
    val totalBytes: Long
    val fileManifestSha256: String
    val includeGraphSha256: String
    val ruleManifestSha256: String
    val files: List<FullTreeNinjaManifestFile>
    val edges: List<FullTreeNinjaManifestEdge>
    val rules: List<FullTreeNinjaManifestRule>
    val processAuthority: Boolean
    val runAuthority: Boolean
}

/** Process-free Kotlin/JVM inspection of the fixed strict `ninja-manifest/` TAR.XZ profile. */
object FullTreeNinjaManifestArchive {
    val configurationSha256: String by lazy {
        NinjaManifestCommitment(NINJA_MANIFEST_CONFIGURATION_DOMAIN).apply {
            string(NINJA_MANIFEST_ARCHIVE_ROOT)
            string(NINJA_MANIFEST_ROOT_FILE)
            strings(NINJA_MANIFEST_POLICY)
            long(NINJA_MANIFEST_MAXIMUM_ARCHIVE_BYTES)
            long(NINJA_MANIFEST_MAXIMUM_EXPANDED_ARCHIVE_BYTES)
            long(NINJA_MANIFEST_MAXIMUM_XZ_DECODER_MEMORY_KIB.toLong())
            long(NINJA_MANIFEST_MAXIMUM_ARCHIVE_MEMBERS.toLong())
            long(NINJA_MANIFEST_MAXIMUM_ARCHIVE_INDEX_BYTES)
            long(NINJA_MANIFEST_MAXIMUM_FILES.toLong())
            long(NINJA_MANIFEST_MAXIMUM_FILE_BYTES.toLong())
            long(NINJA_MANIFEST_MAXIMUM_TOTAL_FILE_BYTES)
            long(NINJA_MANIFEST_MAXIMUM_PHYSICAL_LINES.toLong())
            long(NINJA_MANIFEST_MAXIMUM_LOGICAL_LINE_BYTES.toLong())
            long(NINJA_MANIFEST_MAXIMUM_INCLUDE_EDGES.toLong())
            long(NINJA_MANIFEST_MAXIMUM_RULES.toLong())
            long(NINJA_MANIFEST_MAXIMUM_GRAPH_WORK_UNITS)
            long(NINJA_MANIFEST_MAXIMUM_PATH_BYTES.toLong())
            long(NINJA_MANIFEST_MAXIMUM_PATH_COMPONENT_BYTES.toLong())
            long(NINJA_MANIFEST_MAXIMUM_RULE_NAME_BYTES.toLong())
        }.finish()
    }

    /**
     * The only production admission seam: one raw archive path, the separately authenticated root
     * manifest identity and epoch, and ceilings that may only lower the compiled policy maxima.
     */
    fun inspect(
        archivePath: Path,
        expectedRootBytes: Long,
        expectedRootSha256: String,
        sourceDateEpoch: Long,
        limits: FullTreeNinjaManifestArchiveLimits = FullTreeNinjaManifestArchiveLimits(),
    ): FullTreeNinjaManifestSnapshot = try {
        inspectArchive(
            archivePath,
            expectedRootBytes,
            expectedRootSha256,
            sourceDateEpoch,
            limits,
        )
    } catch (failure: FullTreeNinjaManifestArchiveException) {
        throw failure
    } catch (failure: Exception) {
        throw FullTreeNinjaManifestArchiveException(
            "Ninja manifest archive inspection failed: ${failure.message}",
            failure,
        )
    }
}

private fun inspectArchive(
    archivePath: Path,
    expectedRootBytes: Long,
    expectedRootSha256: String,
    sourceDateEpoch: Long,
    limits: FullTreeNinjaManifestArchiveLimits,
): FullTreeNinjaManifestSnapshot {
    if (expectedRootBytes !in 1L..limits.maximumManifestFileBytes.toLong()) {
        ninjaManifestFailure("expected root manifest byte count exceeds its admitted bound")
    }
    requireNinjaManifestDigest(expectedRootSha256, "expected root manifest")
    if (sourceDateEpoch !in 1L..NINJA_MANIFEST_MAXIMUM_USTAR_NUMBER) {
        ninjaManifestFailure("SOURCE_DATE_EPOCH is outside the canonical USTAR range")
    }

    return StableControlFile.open(
        archivePath,
        limits.maximumArchiveBytes,
        "Ninja manifest archive",
    ).use { archive ->
        archive.requireSingleLink("Ninja manifest archive")
        val archiveSha256 = archive.sha256(label = "Ninja manifest archive")
        val collector = NinjaManifestArchiveCollector(limits)
        try {
            BoundedTarXzArchive.scanGeneratedSnapshot(
                source = StableNinjaManifestArchiveSource(archive),
                expectedRoot = NINJA_MANIFEST_ARCHIVE_ROOT,
                expectedMtime = sourceDateEpoch,
                limits = BoundedTarXzLimits(
                    maximumCompressedBytes = limits.maximumArchiveBytes,
                    maximumExpandedBytes = limits.maximumExpandedArchiveBytes,
                    maximumDecoderMemoryKiB = limits.maximumXzDecoderMemoryKiB,
                    maximumMembers = limits.maximumArchiveMembers,
                    maximumMetadataBytes = 1,
                    maximumEntryBytes = limits.maximumManifestFileBytes.toLong(),
                    maximumPathBytes = limits.maximumPathBytes,
                    maximumComponentBytes = limits.maximumPathComponentBytes,
                    maximumLinkBytes = 1,
                    maximumIndexBytes = limits.maximumArchiveIndexBytes,
                    maximumSelectedBytes = 0,
                ),
                regularFileVisitor = collector,
                onEntry = collector::recordEntry,
            )
        } catch (failure: BoundedTarXzException) {
            throw FullTreeNinjaManifestArchiveException(
                "Ninja manifest archive violates its strict TAR.XZ profile: ${failure.message}",
                failure,
            )
        }
        val collected = collector.finish()
        archive.verifyUnchanged("Ninja manifest archive")
        deriveNinjaManifestSnapshot(
            archive.size,
            archiveSha256,
            expectedRootBytes,
            expectedRootSha256,
            sourceDateEpoch,
            collected,
            limits,
        )
    }
}

private fun deriveNinjaManifestSnapshot(
    archiveBytes: Long,
    archiveSha256: String,
    expectedRootBytes: Long,
    expectedRootSha256: String,
    sourceDateEpoch: Long,
    archive: CollectedNinjaManifestArchive,
    limits: FullTreeNinjaManifestArchiveLimits,
): FullTreeNinjaManifestSnapshot {
    val root = archive.files[NINJA_MANIFEST_ROOT_FILE]
        ?: ninjaManifestFailure("Ninja manifest archive is missing its root build.ninja")
    if (root.size.toLong() != expectedRootBytes || ninjaManifestSha256(root) != expectedRootSha256) {
        ninjaManifestFailure("root build.ninja differs from its separately authenticated byte identity")
    }

    val work = NinjaManifestWorkBudget(limits.maximumGraphWorkUnits)
    val reachable = LinkedHashSet<String>()
    val pending = ArrayDeque<String>()
    val edges = ArrayList<ValidatedNinjaManifestEdge>()
    val rules = ArrayList<ValidatedNinjaManifestRule>()
    val edgeKeys = HashSet<Pair<String, String>>()
    val ruleNames = HashSet<String>()
    reachable += NINJA_MANIFEST_ROOT_FILE
    pending += NINJA_MANIFEST_ROOT_FILE
    var physicalLines = 0L

    while (pending.isNotEmpty()) {
        val sourcePath = pending.removeFirst()
        work.charge("while traversing the Ninja manifest closure")
        val parsed = parseNinjaManifest(
            sourcePath,
            checkNotNull(archive.files[sourcePath]),
            limits,
            work,
        )
        physicalLines = addNinjaManifestBounded(
            physicalLines,
            parsed.physicalLines.toLong(),
            limits.maximumPhysicalLines.toLong(),
            "physical-line",
        )
        parsed.edges.forEach { edge ->
            if (edges.size >= limits.maximumIncludeEdges) {
                ninjaManifestFailure("Ninja manifest closure exceeds its include-edge bound")
            }
            if (!edgeKeys.add(edge.sourcePath to edge.targetPath)) {
                ninjaManifestFailure(
                    "Ninja manifest closure repeats an include edge from ${edge.sourcePath} to ${edge.targetPath}",
                )
            }
            if (edge.targetPath !in archive.files) {
                ninjaManifestFailure(
                    "Ninja manifest ${edge.sourcePath}:${edge.line} references absent ${edge.targetPath}",
                )
            }
            edges += edge
            if (reachable.add(edge.targetPath)) pending += edge.targetPath
            work.charge("while traversing a Ninja include edge")
        }
        parsed.rules.forEach { rule ->
            if (rules.size >= limits.maximumRules) {
                ninjaManifestFailure("Ninja manifest closure exceeds its rule bound")
            }
            if (!ruleNames.add(rule.name)) {
                ninjaManifestFailure("Ninja manifest closure repeats rule declaration ${rule.name}")
            }
            rules += rule
            work.charge("while indexing a Ninja rule")
        }
    }

    if (archive.files.keys != reachable) {
        val extra = TreeSet(FULL_TREE_CODE_POINT_ORDER).apply {
            addAll(archive.files.keys)
            removeAll(reachable)
        }.firstOrNull()
        ninjaManifestFailure("Ninja manifest archive contains unreachable extra file $extra")
    }
    requireAcyclicNinjaManifestClosure(reachable, edges, work)
    requireExactNinjaManifestDirectories(reachable, archive.directories)

    val orderedPaths = reachable.sortedWith(FULL_TREE_CODE_POINT_ORDER)
    val files = orderedPaths.map { path ->
        val bytes = checkNotNull(archive.files[path])
        ValidatedNinjaManifestFile(path, bytes.size.toLong(), ninjaManifestSha256(bytes))
    }
    edges.sortWith(
        compareBy<ValidatedNinjaManifestEdge, String>(FULL_TREE_CODE_POINT_ORDER) { it.sourcePath }
            .thenBy { it.line }
            .thenBy { it.kind.name }
            .thenBy(FULL_TREE_CODE_POINT_ORDER) { it.targetPath },
    )
    rules.sortWith(
        compareBy<ValidatedNinjaManifestRule, String>(FULL_TREE_CODE_POINT_ORDER) { it.name }
            .thenBy(FULL_TREE_CODE_POINT_ORDER) { it.sourcePath }
            .thenBy { it.line },
    )
    val fileManifestSha256 = NinjaManifestCommitment(NINJA_MANIFEST_FILE_DOMAIN).apply {
        long(files.size.toLong())
        files.forEach { file ->
            string(file.path)
            long(file.bytes)
            string(file.sha256)
        }
    }.finish()
    val includeGraphSha256 = NinjaManifestCommitment(NINJA_MANIFEST_EDGE_DOMAIN).apply {
        long(edges.size.toLong())
        edges.forEach { edge ->
            string(edge.sourcePath)
            long(edge.line.toLong())
            string(edge.kind.name.lowercase())
            string(edge.targetPath)
        }
    }.finish()
    val ruleManifestSha256 = NinjaManifestCommitment(NINJA_MANIFEST_RULE_DOMAIN).apply {
        long(rules.size.toLong())
        rules.forEach { rule ->
            string(rule.name)
            string(rule.sourcePath)
            long(rule.line.toLong())
        }
    }.finish()
    val reportSha256 = NinjaManifestCommitment(NINJA_MANIFEST_REPORT_DOMAIN).apply {
        string(FullTreeNinjaManifestArchive.configurationSha256)
        long(archiveBytes)
        string(archiveSha256)
        string(NINJA_MANIFEST_ARCHIVE_ROOT)
        string(NINJA_MANIFEST_ROOT_FILE)
        long(expectedRootBytes)
        string(expectedRootSha256)
        long(sourceDateEpoch)
        long(archive.totalBytes)
        string(fileManifestSha256)
        string(includeGraphSha256)
        string(ruleManifestSha256)
    }.finish()
    return ValidatedNinjaManifestSnapshot(
        archiveBytes,
        archiveSha256,
        FullTreeNinjaManifestArchive.configurationSha256,
        reportSha256,
        archive.totalBytes,
        fileManifestSha256,
        includeGraphSha256,
        ruleManifestSha256,
        files,
        edges,
        rules,
    )
}

private fun parseNinjaManifest(
    sourcePath: String,
    bytes: ByteArray,
    limits: FullTreeNinjaManifestArchiveLimits,
    work: NinjaManifestWorkBudget,
): ParsedNinjaManifest {
    requireStrictNinjaManifestText(sourcePath, bytes, limits)
    val text = try {
        StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes))
            .toString()
    } catch (failure: Exception) {
        throw FullTreeNinjaManifestArchiveException("Ninja manifest $sourcePath is not strict UTF-8", failure)
    }
    if (text.startsWith('\uFEFF')) {
        ninjaManifestFailure("Ninja manifest $sourcePath has a forbidden UTF-8 byte-order mark")
    }

    val edges = ArrayList<ValidatedNinjaManifestEdge>()
    val rules = ArrayList<ValidatedNinjaManifestRule>()
    val lines = text.dropLast(1).split('\n')
    var continuation = false
    var logicalBytes = 0L
    lines.forEachIndexed { index, line ->
        val lineNumber = index + 1
        work.charge("while parsing Ninja manifest $sourcePath")
        val lineBytes = line.toByteArray(StandardCharsets.UTF_8).size.toLong()
        logicalBytes = if (continuation) {
            addNinjaManifestBounded(
                logicalBytes,
                lineBytes,
                limits.maximumLogicalLineBytes.toLong(),
                "logical-line",
            )
        } else {
            if (lineBytes > limits.maximumLogicalLineBytes.toLong()) {
                ninjaManifestFailure("Ninja manifest $sourcePath:$lineNumber exceeds its logical-line bound")
            }
            lineBytes
        }
        val wholeLineComment = !continuation && isNinjaWholeLineComment(line)
        val continues = !wholeLineComment && hasNinjaLineContinuation(line)
        if (!continuation && line.startsWith('\t')) {
            ninjaManifestFailure("Ninja manifest $sourcePath:$lineNumber starts with a forbidden tab")
        }
        if (!continuation && !wholeLineComment && line.isNotEmpty() && line[0] != ' ') {
            val tokenEnd = line.indexOfFirst { !isNinjaManifestIdentifierCharacter(it) }
                .let { if (it < 0) line.length else it }
            val token = line.substring(0, tokenEnd)
            if (token == "include" || token == "subninja" || token == "rule") {
                if (continues) {
                    ninjaManifestFailure(
                        "Ninja manifest $sourcePath:$lineNumber continues a top-level $token declaration",
                    )
                }
                val literal = requireCanonicalNinjaDirectiveArgument(
                    line,
                    tokenEnd,
                    sourcePath,
                    lineNumber,
                    token,
                )
                if (token == "rule") {
                    requireLiteralNinjaRuleName(literal, sourcePath, lineNumber, limits)
                    rules += ValidatedNinjaManifestRule(sourcePath, lineNumber, literal)
                } else {
                    requireLiteralNinjaManifestPath(literal, limits, "$sourcePath:$lineNumber $token target")
                    edges += ValidatedNinjaManifestEdge(
                        sourcePath,
                        lineNumber,
                        if (token == "include") {
                            FullTreeNinjaManifestEdgeKind.INCLUDE
                        } else {
                            FullTreeNinjaManifestEdgeKind.SUBNINJA
                        },
                        literal,
                    )
                }
            }
        }
        continuation = continues
        if (!continuation) logicalBytes = 0L
    }
    if (continuation) ninjaManifestFailure("Ninja manifest $sourcePath ends inside a line continuation")
    return ParsedNinjaManifest(lines.size, edges, rules)
}

private fun isNinjaWholeLineComment(line: String): Boolean {
    val marker = line.indexOfFirst { it != ' ' }
    return marker >= 0 && line[marker] == '#'
}

private fun isNinjaManifestIdentifierCharacter(character: Char): Boolean =
    character in 'a'..'z' || character in 'A'..'Z' || character in '0'..'9' ||
        character == '_' || character == '.' || character == '-'

private fun requireCanonicalNinjaDirectiveArgument(
    line: String,
    tokenEnd: Int,
    sourcePath: String,
    lineNumber: Int,
    token: String,
): String {
    val suffix = line.substring(tokenEnd)
    if (suffix.isEmpty() || suffix[0] != ' ' || '\t' in suffix) {
        ninjaManifestFailure(
            "Ninja manifest $sourcePath:$lineNumber has a noncanonical top-level $token declaration",
        )
    }
    val argumentStart = suffix.indexOfFirst { it != ' ' }
    if (argumentStart < 0) {
        ninjaManifestFailure(
            "Ninja manifest $sourcePath:$lineNumber has an empty top-level $token declaration",
        )
    }
    val argumentEnd = suffix.indexOf(' ', argumentStart).let { if (it < 0) suffix.length else it }
    if (suffix.substring(argumentEnd).any { it != ' ' }) {
        ninjaManifestFailure(
            "Ninja manifest $sourcePath:$lineNumber has multiple or non-literal $token arguments",
        )
    }
    return suffix.substring(argumentStart, argumentEnd)
}

private fun requireStrictNinjaManifestText(
    path: String,
    bytes: ByteArray,
    limits: FullTreeNinjaManifestArchiveLimits,
) {
    if (bytes.isEmpty() || bytes.last() != '\n'.code.toByte()) {
        ninjaManifestFailure("Ninja manifest $path must be nonempty and end with LF")
    }
    var lineBytes = 0
    var lineCount = 0
    bytes.forEach { raw ->
        val value = raw.toInt() and 0xff
        if (value == '\n'.code) {
            lineCount++
            lineBytes = 0
        } else {
            if (value == '\r'.code || value == 0x7f || value < 0x20 && value != '\t'.code) {
                ninjaManifestFailure("Ninja manifest $path contains a forbidden control byte")
            }
            lineBytes++
            if (lineBytes > limits.maximumLogicalLineBytes) {
                ninjaManifestFailure("Ninja manifest $path has an overlong physical line")
            }
        }
    }
    if (lineCount > limits.maximumPhysicalLines) {
        ninjaManifestFailure("Ninja manifest $path exceeds its physical-line bound")
    }
}

private fun hasNinjaLineContinuation(line: String): Boolean {
    var dollars = 0
    var index = line.length - 1
    while (index >= 0 && line[index] == '$') {
        dollars++
        index--
    }
    return dollars % 2 == 1
}

private fun requireLiteralNinjaManifestPath(
    path: String,
    limits: FullTreeNinjaManifestArchiveLimits,
    label: String,
) {
    val encoded = path.toByteArray(StandardCharsets.US_ASCII)
    if (path.isEmpty() || encoded.size > limits.maximumPathBytes || path.startsWith('/') ||
        path.endsWith('/') || "//" in path || '\\' in path ||
        path.any { character ->
            character.code !in 0x21..0x7e || character == '$' || character == ':' ||
                character == '#' || character == '|'
        }
    ) {
        ninjaManifestFailure("$label is not a canonical literal build-root-relative path")
    }
    val components = path.split('/')
    if (components.any { component ->
            component.isEmpty() || component == "." || component == ".." ||
                component.toByteArray(StandardCharsets.US_ASCII).size > limits.maximumPathComponentBytes
        }
    ) {
        ninjaManifestFailure("$label has an unsafe or overlong path component")
    }
}

private fun requireLiteralNinjaRuleName(
    name: String,
    sourcePath: String,
    line: Int,
    limits: FullTreeNinjaManifestArchiveLimits,
) {
    val bytes = name.toByteArray(StandardCharsets.US_ASCII)
    if (name.isEmpty() || bytes.size > limits.maximumRuleNameBytes ||
        !name.matches(NINJA_MANIFEST_RULE_NAME)
    ) {
        ninjaManifestFailure("Ninja manifest $sourcePath:$line has a non-literal rule name")
    }
}

private fun requireAcyclicNinjaManifestClosure(
    paths: Set<String>,
    edges: List<ValidatedNinjaManifestEdge>,
    work: NinjaManifestWorkBudget,
) {
    val indegree = TreeMap<String, Int>(FULL_TREE_CODE_POINT_ORDER)
    val outgoing = TreeMap<String, MutableList<String>>(FULL_TREE_CODE_POINT_ORDER)
    paths.forEach { path ->
        indegree[path] = 0
        outgoing[path] = ArrayList()
    }
    edges.forEach { edge ->
        outgoing.getValue(edge.sourcePath) += edge.targetPath
        indegree[edge.targetPath] = Math.addExact(indegree.getValue(edge.targetPath), 1)
        work.charge("while constructing the Ninja include graph")
    }
    val ready = TreeSet(FULL_TREE_CODE_POINT_ORDER)
    indegree.filterValues { it == 0 }.keys.forEach(ready::add)
    var consumed = 0
    while (ready.isNotEmpty()) {
        val source = ready.pollFirst()
        consumed++
        outgoing.getValue(source).forEach { target ->
            val remaining = indegree.getValue(target) - 1
            indegree[target] = remaining
            if (remaining == 0) ready += target
            work.charge("while proving the Ninja include graph acyclic")
        }
    }
    if (consumed != paths.size) ninjaManifestFailure("Ninja manifest include graph contains a cycle")
}

private fun requireExactNinjaManifestDirectories(paths: Set<String>, actualDirectories: Set<String>) {
    val expected = TreeSet(FULL_TREE_CODE_POINT_ORDER)
    expected += ""
    paths.forEach { path ->
        val components = path.split('/')
        for (end in 1 until components.size) expected += components.take(end).joinToString("/")
    }
    if (actualDirectories != expected) {
        ninjaManifestFailure("Ninja manifest archive directory population is not the exact closure parent set")
    }
}

private class NinjaManifestArchiveCollector(
    private val limits: FullTreeNinjaManifestArchiveLimits,
) : BoundedTarXzRegularFileVisitor {
    private val files = TreeMap<String, ByteArray>(FULL_TREE_CODE_POINT_ORDER)
    private val directories = TreeSet<String>(FULL_TREE_CODE_POINT_ORDER)
    private var totalBytes = 0L
    private var current: CurrentNinjaManifestFile? = null

    fun recordEntry(entry: BoundedTarEntry) {
        val relative = entry.relativePath
        when (entry.kind) {
            BoundedTarEntryKind.DIRECTORY -> {
                if (relative.isNotEmpty()) {
                    requireLiteralNinjaManifestPath(relative, limits, "Ninja manifest archive directory")
                }
                if (!directories.add(relative)) ninjaManifestFailure("Ninja manifest archive repeats a directory")
            }
            BoundedTarEntryKind.REGULAR -> {
                requireLiteralNinjaManifestPath(relative, limits, "Ninja manifest archive member")
                if (files.size >= limits.maximumManifestFiles) {
                    ninjaManifestFailure("Ninja manifest archive exceeds its file-count bound")
                }
                totalBytes = addNinjaManifestBounded(
                    totalBytes,
                    entry.size,
                    limits.maximumTotalManifestBytes,
                    "manifest-payload",
                )
            }
            BoundedTarEntryKind.SYMBOLIC_LINK -> ninjaManifestFailure(
                "Ninja manifest archive cannot contain symbolic links",
            )
        }
    }

    override fun wants(entry: BoundedTarEntry): Boolean {
        if (current != null) ninjaManifestFailure("Ninja manifest archive visitor overlapped file payloads")
        current = CurrentNinjaManifestFile(
            entry.relativePath,
            entry.size.toInt(),
            ByteArrayOutputStream(entry.size.toInt()),
        )
        return true
    }

    override fun onChunk(entry: BoundedTarEntry, bytes: ByteArray, length: Int, endOfEntry: Boolean) {
        val selected = current ?: ninjaManifestFailure("Ninja manifest archive delivered an unselected payload")
        if (selected.path != entry.relativePath || length !in 0..bytes.size) {
            ninjaManifestFailure("Ninja manifest archive payload visitor lost member identity")
        }
        selected.output.write(bytes, 0, length)
        if (selected.output.size() > selected.expectedBytes) {
            ninjaManifestFailure("Ninja manifest archive member exceeded its declared byte count")
        }
        if (endOfEntry) {
            if (selected.output.size() != selected.expectedBytes || files.put(selected.path, selected.output.toByteArray()) != null) {
                ninjaManifestFailure("Ninja manifest archive member payload is duplicate or truncated")
            }
            current = null
        }
    }

    fun finish(): CollectedNinjaManifestArchive {
        if (current != null) ninjaManifestFailure("Ninja manifest archive ended inside a file payload")
        if (files.isEmpty()) ninjaManifestFailure("Ninja manifest archive has no regular manifest files")
        return CollectedNinjaManifestArchive(
            Collections.unmodifiableMap(TreeMap(files)),
            Collections.unmodifiableSet(TreeSet(directories)),
            totalBytes,
        )
    }
}

private class StableNinjaManifestArchiveSource(private val archive: StableControlFile) : BoundedTarXzSource {
    override val size: Long = archive.size

    override fun read(position: Long, destination: ByteArray, offset: Int, length: Int): Int =
        archive.readAt(position, destination, offset, length)
}

private class NinjaManifestWorkBudget(private val maximum: Long) {
    private var consumed = 0L

    fun charge(label: String) {
        consumed = try {
            Math.addExact(consumed, 1L)
        } catch (failure: ArithmeticException) {
            throw FullTreeNinjaManifestArchiveException("Ninja manifest graph work overflows $label", failure)
        }
        if (consumed > maximum) ninjaManifestFailure("Ninja manifest exceeds its graph-work bound $label")
    }
}

private class NinjaManifestCommitment(domain: String) {
    private val digest = MessageDigest.getInstance("SHA-256")

    init {
        bytes(domain.toByteArray(StandardCharsets.UTF_8))
    }

    fun string(value: String) = bytes(value.toByteArray(StandardCharsets.UTF_8))

    fun strings(values: List<String>) {
        long(values.size.toLong())
        values.forEach(::string)
    }

    fun long(value: Long) {
        require(value >= 0L)
        digest.update(ByteBuffer.allocate(Long.SIZE_BYTES).putLong(value).array())
    }

    private fun bytes(value: ByteArray) {
        long(value.size.toLong())
        digest.update(value)
    }

    fun finish(): String = digest.digest().joinToString("") { byte ->
        (byte.toInt() and 0xff).toString(16).padStart(2, '0')
    }
}

private data class ValidatedNinjaManifestFile(
    override val path: String,
    override val bytes: Long,
    override val sha256: String,
) : FullTreeNinjaManifestFile

private data class ValidatedNinjaManifestEdge(
    override val sourcePath: String,
    override val line: Int,
    override val kind: FullTreeNinjaManifestEdgeKind,
    override val targetPath: String,
) : FullTreeNinjaManifestEdge

private data class ValidatedNinjaManifestRule(
    override val sourcePath: String,
    override val line: Int,
    override val name: String,
) : FullTreeNinjaManifestRule

private class ValidatedNinjaManifestSnapshot(
    override val archiveBytes: Long,
    override val archiveSha256: String,
    override val configurationSha256: String,
    override val reportSha256: String,
    override val totalBytes: Long,
    override val fileManifestSha256: String,
    override val includeGraphSha256: String,
    override val ruleManifestSha256: String,
    files: List<FullTreeNinjaManifestFile>,
    edges: List<FullTreeNinjaManifestEdge>,
    rules: List<FullTreeNinjaManifestRule>,
) : FullTreeNinjaManifestSnapshot {
    override val archiveRoot: String = NINJA_MANIFEST_ARCHIVE_ROOT
    override val rootManifest: String = NINJA_MANIFEST_ROOT_FILE
    override val files: List<FullTreeNinjaManifestFile> =
        Collections.unmodifiableList(ArrayList(files))
    override val edges: List<FullTreeNinjaManifestEdge> =
        Collections.unmodifiableList(ArrayList(edges))
    override val rules: List<FullTreeNinjaManifestRule> =
        Collections.unmodifiableList(ArrayList(rules))
    override val processAuthority: Boolean = false
    override val runAuthority: Boolean = false
}

private data class CurrentNinjaManifestFile(
    val path: String,
    val expectedBytes: Int,
    val output: ByteArrayOutputStream,
)

private data class CollectedNinjaManifestArchive(
    val files: Map<String, ByteArray>,
    val directories: Set<String>,
    val totalBytes: Long,
)

private data class ParsedNinjaManifest(
    val physicalLines: Int,
    val edges: List<ValidatedNinjaManifestEdge>,
    val rules: List<ValidatedNinjaManifestRule>,
)

private fun addNinjaManifestBounded(current: Long, added: Long, maximum: Long, label: String): Long {
    val result = try {
        Math.addExact(current, added)
    } catch (failure: ArithmeticException) {
        throw FullTreeNinjaManifestArchiveException("Ninja manifest $label byte count overflows", failure)
    }
    if (result > maximum) ninjaManifestFailure("Ninja manifest exceeds its $label bound")
    return result
}

private fun requireNinjaManifestDigest(value: String, label: String) {
    if (!value.matches(Regex("[0-9a-f]{64}"))) ninjaManifestFailure("$label SHA-256 is invalid")
}

private fun ninjaManifestSha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
    .digest(bytes)
    .joinToString("") { byte -> (byte.toInt() and 0xff).toString(16).padStart(2, '0') }

private fun ninjaManifestFailure(message: String): Nothing =
    throw FullTreeNinjaManifestArchiveException(message)

private const val NINJA_MANIFEST_ARCHIVE_ROOT = "ninja-manifest"
private const val NINJA_MANIFEST_ROOT_FILE = "build.ninja"
private const val NINJA_MANIFEST_MAXIMUM_ARCHIVE_BYTES = 64L * 1024L * 1024L
private const val NINJA_MANIFEST_MAXIMUM_EXPANDED_ARCHIVE_BYTES = 256L * 1024L * 1024L
private const val NINJA_MANIFEST_MAXIMUM_XZ_DECODER_MEMORY_KIB = 256 * 1024
private const val NINJA_MANIFEST_MAXIMUM_ARCHIVE_MEMBERS = 10_000
private const val NINJA_MANIFEST_MAXIMUM_ARCHIVE_INDEX_BYTES = 16L * 1024L * 1024L
private const val NINJA_MANIFEST_MAXIMUM_FILES = 4_096
private const val NINJA_MANIFEST_MAXIMUM_FILE_BYTES = 32 * 1024 * 1024
private const val NINJA_MANIFEST_MAXIMUM_TOTAL_FILE_BYTES = 128L * 1024L * 1024L
private const val NINJA_MANIFEST_MAXIMUM_PHYSICAL_LINES = 2_000_000
private const val NINJA_MANIFEST_MAXIMUM_LOGICAL_LINE_BYTES = 1024 * 1024
private const val NINJA_MANIFEST_MAXIMUM_INCLUDE_EDGES = 32_768
private const val NINJA_MANIFEST_MAXIMUM_RULES = 65_536
private const val NINJA_MANIFEST_MAXIMUM_GRAPH_WORK_UNITS = 10_000_000L
private const val NINJA_MANIFEST_MAXIMUM_PATH_BYTES = 4096
private const val NINJA_MANIFEST_MAXIMUM_PATH_COMPONENT_BYTES = 255
private const val NINJA_MANIFEST_MAXIMUM_RULE_NAME_BYTES = 256
private const val NINJA_MANIFEST_MAXIMUM_USTAR_NUMBER = 0x1ffffffffL
private const val NINJA_MANIFEST_CONFIGURATION_DOMAIN =
    "decomp-thing/full-tree-ninja-manifest-archive-configuration/v1"
private val NINJA_MANIFEST_RULE_NAME = Regex("[A-Za-z0-9_.-]+")
private const val NINJA_MANIFEST_FILE_DOMAIN =
    "decomp-thing/full-tree-ninja-manifest-file-manifest/v1"
private const val NINJA_MANIFEST_EDGE_DOMAIN =
    "decomp-thing/full-tree-ninja-manifest-include-graph/v1"
private const val NINJA_MANIFEST_RULE_DOMAIN =
    "decomp-thing/full-tree-ninja-manifest-rule-manifest/v1"
private const val NINJA_MANIFEST_REPORT_DOMAIN =
    "decomp-thing/full-tree-ninja-manifest-archive-report/v1"
private val NINJA_MANIFEST_POLICY = listOf(
    "strict-single-stream-crc64-ustar-xz",
    "fixed-ninja-manifest-root",
    "exact-source-date-epoch",
    "regular-files-and-required-directories-only",
    "strict-utf8-lf-text",
    "ninja-1.11.1-comment-and-directive-token-semantics",
    "literal-top-level-include-subninja-closure",
    "no-unreachable-files-or-directories",
    "no-duplicate-edges-or-cycles",
    "globally-unique-literal-top-level-rule-declarations",
    "build-root-relative-include-resolution",
    "process-free-no-run-authority",
)
