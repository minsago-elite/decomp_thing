package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.ArrayDeque
import java.util.Collections
import java.util.PriorityQueue
import java.util.TreeMap
import java.util.TreeSet
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

internal class FullTreeHeaderModulePlanException(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

/** One authenticated planning module. Module IDs remain the exact A13 compilation-unit IDs. */
internal data class FullTreeHeaderPlanningModule(
    val moduleId: String,
    val shardId: String,
    val sourcePath: String,
    val unresolvedBlockerCount: Int = 0,
)

/** One canonical header. Its owner ID is derived internally from the complete path. */
internal data class FullTreeCanonicalHeader(
    val sourcePath: String,
    val unresolvedBlockerCount: Int = 0,
)

/** A source-only unit is retained for exclusion checks and can never become a graph node or owner. */
internal data class FullTreeHeaderSourceOnlyUnit(
    val shardId: String,
    val sourcePath: String,
)

/** Per-TU evidence that a compiler trace reached a canonical project header. */
internal data class FullTreeObservedHeaderUse(
    val observingModuleId: String,
    val headerPath: String,
)

/** A direct file edge already resolved by an authenticated compiler-resolution boundary. */
internal data class FullTreeResolvedDirectFileEdge(
    val observingModuleId: String,
    val consumerPath: String,
    val dependencyHeaderPath: String,
)

internal enum class FullTreeHeaderResolutionBlockerKind(val wireName: String) {
    AMBIGUOUS("ambiguous"),
    COMPILER_TRACE_UNAUTHENTICATED("compiler-trace-unauthenticated"),
    CONDITIONAL("conditional"),
    EXTERNAL_INCLUDE("external-include"),
    MACRO("macro"),
    MODULE_IMPORT("module-import"),
    NONSTANDARD("nonstandard"),
    NON_HEADER_PROJECT_TARGET("non-header-project-target"),
    OUT_OF_SCOPE_CONSUMER("out-of-scope-consumer"),
    GENERATED_INPUT_MISSING("generated-input-missing"),
    UNRESOLVED("unresolved"),
}

/** Accounted unresolved evidence. Raw spellings stay outside this bounded fixture checkpoint. */
internal data class FullTreeHeaderResolutionBlocker(
    val consumerPath: String,
    val kind: FullTreeHeaderResolutionBlockerKind,
    val evidenceSha256: String,
)

internal data class FullTreeHeaderModulePlanLimits(
    val maximumModules: Int = HEADER_PLAN_MAXIMUM_MODULES,
    val maximumHeaders: Int = HEADER_PLAN_MAXIMUM_HEADERS,
    val maximumSourceOnlyUnits: Int = HEADER_PLAN_MAXIMUM_SOURCE_ONLY_UNITS,
    val maximumHeaderObservations: Int = HEADER_PLAN_MAXIMUM_HEADER_OBSERVATIONS,
    val maximumDirectEdges: Int = HEADER_PLAN_MAXIMUM_DIRECT_EDGES,
    val maximumBlockers: Int = HEADER_PLAN_MAXIMUM_BLOCKERS,
    val maximumGraphNodes: Int = HEADER_PLAN_MAXIMUM_GRAPH_NODES,
    val maximumCondensationEdges: Int = HEADER_PLAN_MAXIMUM_CONDENSATION_EDGES,
    val maximumWorkUnits: Long = HEADER_PLAN_MAXIMUM_WORK_UNITS,
    val maximumSerializedBytes: Int = HEADER_PLAN_MAXIMUM_SERIALIZED_BYTES,
) {
    init {
        require(maximumModules in 1..HEADER_PLAN_MAXIMUM_MODULES)
        require(maximumHeaders in 1..HEADER_PLAN_MAXIMUM_HEADERS)
        require(maximumSourceOnlyUnits in 1..HEADER_PLAN_MAXIMUM_SOURCE_ONLY_UNITS)
        require(maximumHeaderObservations in 1..HEADER_PLAN_MAXIMUM_HEADER_OBSERVATIONS)
        require(maximumDirectEdges in 1..HEADER_PLAN_MAXIMUM_DIRECT_EDGES)
        require(maximumBlockers in 1..HEADER_PLAN_MAXIMUM_BLOCKERS)
        require(maximumGraphNodes in 1..HEADER_PLAN_MAXIMUM_GRAPH_NODES)
        require(maximumCondensationEdges in 1..HEADER_PLAN_MAXIMUM_CONDENSATION_EDGES)
        require(maximumWorkUnits in 1L..HEADER_PLAN_MAXIMUM_WORK_UNITS)
        require(maximumSerializedBytes in 1..HEADER_PLAN_MAXIMUM_SERIALIZED_BYTES)
    }
}

internal sealed interface FullTreeHeaderModulePlanResult {
    val complete: Boolean
    val moduleCount: Int
    val headerCount: Int
    val sourceOnlyCount: Int
    val headerObservationCount: Int
    val directEdgeCount: Int
    val blockerCount: Int
    val componentCount: Int
    val condensationEdgeCount: Int
    val workUnits: Long
    val reportSha256: String
    val canonicalBytes: ByteArray
}

/**
 * Fixture-complete, non-authoritative header ownership and module-graph checkpoint.
 *
 * The builder accepts no owner ID, graph node, SCC, edge identity, parsed JSON, or callback. Every
 * header receives a full SHA-256 owner ID derived from its canonical path. Direct edges may name
 * only planning-module or header consumers and canonical header dependencies. Explicit blocker
 * counts must equal the supplied blocker records; accounted blockers retain a deterministic known
 * graph while fixing [FullTreeHeaderModulePlanResult.complete] to false.
 */
internal object FullTreeHeaderModulePlan {
    fun build(
        modules: List<FullTreeHeaderPlanningModule>,
        headers: List<FullTreeCanonicalHeader>,
        sourceOnlyUnits: List<FullTreeHeaderSourceOnlyUnit>,
        headerObservations: List<FullTreeObservedHeaderUse>,
        directEdges: List<FullTreeResolvedDirectFileEdge>,
        blockers: List<FullTreeHeaderResolutionBlocker>,
        limits: FullTreeHeaderModulePlanLimits = FullTreeHeaderModulePlanLimits(),
    ): FullTreeHeaderModulePlanResult = buildHeaderModulePlan(
        modules.toList(),
        headers.toList(),
        sourceOnlyUnits.toList(),
        headerObservations.toList(),
        directEdges.toList(),
        blockers.toList(),
        limits,
    )
}

private class ValidatedHeaderModulePlan(
    override val complete: Boolean,
    override val moduleCount: Int,
    override val headerCount: Int,
    override val sourceOnlyCount: Int,
    override val headerObservationCount: Int,
    override val directEdgeCount: Int,
    override val blockerCount: Int,
    override val componentCount: Int,
    override val condensationEdgeCount: Int,
    override val workUnits: Long,
    override val reportSha256: String,
    canonicalBytes: ByteArray,
) : FullTreeHeaderModulePlanResult {
    private val storedCanonicalBytes = canonicalBytes.copyOf()

    override val canonicalBytes: ByteArray
        get() = storedCanonicalBytes.copyOf()
}

private data class ValidatedModule(
    val moduleId: String,
    val shardId: String,
    val sourcePath: String,
    val unresolvedBlockerCount: Int,
)

private data class ValidatedHeader(
    val headerOwnerId: String,
    val sourcePath: String,
    val unresolvedBlockerCount: Int,
)

private data class ValidatedSourceOnly(
    val shardId: String,
    val sourcePath: String,
)

private data class ValidatedHeaderObservation(
    val observingModuleId: String,
    val observingShardId: String,
    val headerOwnerId: String,
    val headerPath: String,
)

private data class ValidatedDirectEdge(
    val observingModuleId: String,
    val observingShardId: String,
    val consumerPath: String,
    val dependencyHeaderPath: String,
    val consumerNodeId: String,
    val dependencyNodeId: String,
)

private data class ValidatedBlocker(
    val blockerId: String,
    val consumerPath: String,
    val consumerNodeId: String,
    val kind: FullTreeHeaderResolutionBlockerKind,
    val evidenceSha256: String,
)

private enum class HeaderPlanNodeKind(val wireName: String) {
    MODULE("planning-module"),
    HEADER("canonical-header-owner"),
}

private data class HeaderPlanNode(
    val nodeId: String,
    val kind: HeaderPlanNodeKind,
    val sourcePath: String,
    val shardId: String?,
)

private data class HeaderPlanComponent(
    val componentId: String,
    val memberNodeIds: List<String>,
    val moduleIds: List<String>,
    val headerOwnerIds: List<String>,
)

private data class HeaderPlanCondensationEdge(
    val dependencyComponentId: String,
    val consumerComponentId: String,
)

private data class HeaderPlanGraph(
    val components: List<HeaderPlanComponent>,
    val edges: List<HeaderPlanCondensationEdge>,
    val kahnOrder: List<String>,
)

private data class HeaderPlanBoundaryFacts(
    val componentMemberShardIds: Map<String, List<String>>,
    val componentConsumerShardIds: Map<String, List<String>>,
    val headerConsumerShardIds: Map<String, List<String>>,
)

private fun buildHeaderModulePlan(
    rawModules: List<FullTreeHeaderPlanningModule>,
    rawHeaders: List<FullTreeCanonicalHeader>,
    rawSourceOnly: List<FullTreeHeaderSourceOnlyUnit>,
    rawHeaderObservations: List<FullTreeObservedHeaderUse>,
    rawDirectEdges: List<FullTreeResolvedDirectFileEdge>,
    rawBlockers: List<FullTreeHeaderResolutionBlocker>,
    limits: FullTreeHeaderModulePlanLimits,
): FullTreeHeaderModulePlanResult {
    requireInputCounts(
        rawModules,
        rawHeaders,
        rawSourceOnly,
        rawHeaderObservations,
        rawDirectEdges,
        rawBlockers,
        limits,
    )
    val work = HeaderPlanWorkBudget(limits.maximumWorkUnits)

    val modules = validateModules(rawModules, limits, work)
    val headers = validateHeaders(rawHeaders, limits, work)
    val sourceOnly = validateSourceOnly(rawSourceOnly, work)
    val nodes = TreeMap<String, HeaderPlanNode>(FULL_TREE_CODE_POINT_ORDER)
    val nodeIdByPath = TreeMap<String, String>(FULL_TREE_CODE_POINT_ORDER)
    val sourceOnlyPaths = TreeSet<String>(FULL_TREE_CODE_POINT_ORDER)

    modules.forEach { module ->
        addPlanNode(
            nodes,
            nodeIdByPath,
            HeaderPlanNode(module.moduleId, HeaderPlanNodeKind.MODULE, module.sourcePath, module.shardId),
            work,
        )
    }
    headers.forEach { header ->
        addPlanNode(
            nodes,
            nodeIdByPath,
            HeaderPlanNode(header.headerOwnerId, HeaderPlanNodeKind.HEADER, header.sourcePath, null),
            work,
        )
    }
    sourceOnly.forEach { unit ->
        work.charge("source-only exclusion")
        if (!sourceOnlyPaths.add(unit.sourcePath) || unit.sourcePath in nodeIdByPath) {
            headerPlanFail("source-only path aliases a planning module, header, or duplicate source-only unit")
        }
    }
    if (nodes.size != modules.size + headers.size || nodes.size > limits.maximumGraphNodes) {
        headerPlanFail("header module plan exceeds its graph-node bound")
    }

    val headerObservations = validateHeaderObservations(
        rawHeaderObservations,
        modules,
        headers,
        work,
    )

    val blockers = validateBlockers(
        rawBlockers,
        modules,
        headers,
        nodeIdByPath,
        sourceOnlyPaths,
        work,
    )
    val directEdges = validateDirectEdges(
        rawDirectEdges,
        modules,
        headers,
        nodeIdByPath,
        sourceOnlyPaths,
        headerObservations,
        work,
    )
    requireExactBlockerAccounting(modules, headers, blockers)

    val adjacency = emptyAdjacency(nodes.keys)
    val reverseAdjacency = emptyAdjacency(nodes.keys)
    directEdges.forEach { edge ->
        work.charge("direct graph edge")
        adjacency.getValue(edge.consumerNodeId).add(edge.dependencyNodeId)
        reverseAdjacency.getValue(edge.dependencyNodeId).add(edge.consumerNodeId)
    }
    val graph = buildCondensationGraph(nodes, adjacency, reverseAdjacency, limits, work)
    val boundaries = buildHeaderPlanBoundaries(nodes, headerObservations, graph, work)
    val directConsumerPaths = directEdges.mapTo(HashSet(), ValidatedDirectEdge::consumerPath)
    val isolatedModules = modules.count { it.sourcePath !in directConsumerPaths }
    val complete = blockers.isEmpty()

    work.charge(
        modules.size.toLong() + headers.size.toLong() + sourceOnly.size.toLong() +
            headerObservations.size.toLong() +
            directEdges.size.toLong() + blockers.size.toLong() + graph.components.size.toLong() +
            graph.edges.size.toLong() + graph.kahnOrder.size.toLong(),
        "canonical output record",
    )
    val withoutReport = renderHeaderModulePlan(
        modules,
        headers,
        sourceOnly,
        headerObservations,
        directEdges,
        blockers,
        graph,
        boundaries,
        complete,
        isolatedModules,
        work.used,
        limits,
    )
    val reportSha256 = OracleArtifacts.sha256(canonicalHeaderPlanBytes(withoutReport, limits))
    val document = JsonObject(withoutReport + ("reportSha256" to JsonPrimitive(reportSha256)))
    val canonicalBytes = canonicalHeaderPlanBytes(document, limits)
    return ValidatedHeaderModulePlan(
        complete = complete,
        moduleCount = modules.size,
        headerCount = headers.size,
        sourceOnlyCount = sourceOnly.size,
        headerObservationCount = headerObservations.size,
        directEdgeCount = directEdges.size,
        blockerCount = blockers.size,
        componentCount = graph.components.size,
        condensationEdgeCount = graph.edges.size,
        workUnits = work.used,
        reportSha256 = reportSha256,
        canonicalBytes = canonicalBytes,
    )
}

private fun requireInputCounts(
    modules: List<FullTreeHeaderPlanningModule>,
    headers: List<FullTreeCanonicalHeader>,
    sourceOnly: List<FullTreeHeaderSourceOnlyUnit>,
    headerObservations: List<FullTreeObservedHeaderUse>,
    directEdges: List<FullTreeResolvedDirectFileEdge>,
    blockers: List<FullTreeHeaderResolutionBlocker>,
    limits: FullTreeHeaderModulePlanLimits,
) {
    if (modules.isEmpty()) headerPlanFail("header module plan requires at least one planning module")
    if (modules.size > limits.maximumModules) headerPlanFail("header module plan exceeds its module bound")
    if (headers.size > limits.maximumHeaders) headerPlanFail("header module plan exceeds its header bound")
    if (sourceOnly.size > limits.maximumSourceOnlyUnits) {
        headerPlanFail("header module plan exceeds its source-only bound")
    }
    if (headerObservations.size > limits.maximumHeaderObservations) {
        headerPlanFail("header module plan exceeds its header-observation bound")
    }
    if (directEdges.size > limits.maximumDirectEdges) {
        headerPlanFail("header module plan exceeds its direct-edge bound")
    }
    if (blockers.size > limits.maximumBlockers) headerPlanFail("header module plan exceeds its blocker bound")
    val nodeCount = modules.size.toLong() + headers.size.toLong()
    if (nodeCount > limits.maximumGraphNodes.toLong()) {
        headerPlanFail("header module plan exceeds its graph-node bound")
    }
}

private fun validateModules(
    raw: List<FullTreeHeaderPlanningModule>,
    limits: FullTreeHeaderModulePlanLimits,
    work: HeaderPlanWorkBudget,
): List<ValidatedModule> {
    val byId = TreeMap<String, ValidatedModule>(FULL_TREE_CODE_POINT_ORDER)
    val paths = TreeSet<String>(FULL_TREE_CODE_POINT_ORDER)
    raw.forEach { module ->
        work.charge("planning module")
        if (!HEADER_PLAN_MODULE_ID.matches(module.moduleId)) {
            headerPlanFail("planning module ID is not a canonical compilation-unit ID")
        }
        requireShardId(module.shardId, "planning module")
        requireSourcePath(module.sourcePath, HEADER_PLAN_MODULE_SUFFIXES, "planning module source")
        requireBlockerCount(module.unresolvedBlockerCount, limits, "planning module")
        val validated = ValidatedModule(
            module.moduleId,
            module.shardId,
            module.sourcePath,
            module.unresolvedBlockerCount,
        )
        if (byId.putIfAbsent(module.moduleId, validated) != null || !paths.add(module.sourcePath)) {
            headerPlanFail("planning modules contain a duplicate ID or source path")
        }
    }
    return Collections.unmodifiableList(byId.values.toList())
}

private fun validateHeaders(
    raw: List<FullTreeCanonicalHeader>,
    limits: FullTreeHeaderModulePlanLimits,
    work: HeaderPlanWorkBudget,
): List<ValidatedHeader> {
    val byId = TreeMap<String, ValidatedHeader>(FULL_TREE_CODE_POINT_ORDER)
    val paths = TreeSet<String>(FULL_TREE_CODE_POINT_ORDER)
    raw.forEach { header ->
        work.charge("canonical header")
        requireSourcePath(header.sourcePath, HEADER_PLAN_HEADER_SUFFIXES, "canonical header")
        requireBlockerCount(header.unresolvedBlockerCount, limits, "canonical header")
        val ownerId = headerOwnerId(header.sourcePath)
        val validated = ValidatedHeader(ownerId, header.sourcePath, header.unresolvedBlockerCount)
        if (!paths.add(header.sourcePath) || byId.putIfAbsent(ownerId, validated) != null) {
            headerPlanFail("canonical headers contain a duplicate path or owner-ID collision")
        }
    }
    return Collections.unmodifiableList(byId.values.toList())
}

private fun validateSourceOnly(
    raw: List<FullTreeHeaderSourceOnlyUnit>,
    work: HeaderPlanWorkBudget,
): List<ValidatedSourceOnly> = raw.map { unit ->
    work.charge("source-only unit")
    requireShardId(unit.shardId, "source-only unit")
    requireSourcePath(unit.sourcePath, HEADER_PLAN_MODULE_SUFFIXES, "source-only unit")
    ValidatedSourceOnly(unit.shardId, unit.sourcePath)
}.sortedWith { left, right ->
    FULL_TREE_CODE_POINT_ORDER.compare(left.sourcePath, right.sourcePath).takeIf { it != 0 }
        ?: FULL_TREE_CODE_POINT_ORDER.compare(left.shardId, right.shardId)
}

private fun addPlanNode(
    nodes: MutableMap<String, HeaderPlanNode>,
    nodeIdByPath: MutableMap<String, String>,
    node: HeaderPlanNode,
    work: HeaderPlanWorkBudget,
) {
    work.charge("graph node")
    if (node.nodeId in HEADER_PLAN_CATCH_ALL_IDS || node.sourcePath in HEADER_PLAN_CATCH_ALL_IDS) {
        headerPlanFail("catch-all graph ownership is forbidden")
    }
    if (nodes.putIfAbsent(node.nodeId, node) != null || nodeIdByPath.putIfAbsent(node.sourcePath, node.nodeId) != null) {
        headerPlanFail("graph nodes contain a duplicate ID, path, or cross-kind alias")
    }
}

private fun validateHeaderObservations(
    raw: List<FullTreeObservedHeaderUse>,
    modules: List<ValidatedModule>,
    headers: List<ValidatedHeader>,
    work: HeaderPlanWorkBudget,
): List<ValidatedHeaderObservation> {
    val modulesById = modules.associateBy(ValidatedModule::moduleId)
    val headersByPath = headers.associateBy(ValidatedHeader::sourcePath)
    val identities = TreeSet<String>(FULL_TREE_CODE_POINT_ORDER)
    val result = ArrayList<ValidatedHeaderObservation>(raw.size)
    raw.forEach { observation ->
        work.charge("header observation")
        val observer = modulesById[observation.observingModuleId]
            ?: headerPlanFail("header observation names an unknown module")
        val header = headersByPath[observation.headerPath]
            ?: headerPlanFail("header observation names an unknown canonical header")
        val identity = "${observer.moduleId}\u0000${header.headerOwnerId}"
        if (!identities.add(identity)) headerPlanFail("header observations contain a duplicate")
        result += ValidatedHeaderObservation(
            observer.moduleId,
            observer.shardId,
            header.headerOwnerId,
            header.sourcePath,
        )
    }
    return immutableHeaderPlanList(
        result.sortedWith { left, right ->
            FULL_TREE_CODE_POINT_ORDER.compare(left.observingModuleId, right.observingModuleId)
                .takeIf { it != 0 }
                ?: FULL_TREE_CODE_POINT_ORDER.compare(left.headerOwnerId, right.headerOwnerId)
        },
    )
}

private fun validateDirectEdges(
    raw: List<FullTreeResolvedDirectFileEdge>,
    modules: List<ValidatedModule>,
    headers: List<ValidatedHeader>,
    nodeIdByPath: Map<String, String>,
    sourceOnlyPaths: Set<String>,
    headerObservations: List<ValidatedHeaderObservation>,
    work: HeaderPlanWorkBudget,
): List<ValidatedDirectEdge> {
    val modulesById = modules.associateBy(ValidatedModule::moduleId)
    val moduleIds = modulesById.keys
    val headerIds = headers.associate { it.sourcePath to it.headerOwnerId }
    val headerOwnerIds = headerIds.values.toHashSet()
    val observedHeaders = headerObservations.mapTo(HashSet()) {
        it.observingModuleId to it.headerOwnerId
    }
    val identities = TreeSet<String>(FULL_TREE_CODE_POINT_ORDER)
    val result = ArrayList<ValidatedDirectEdge>(raw.size)
    raw.forEach { edge ->
        work.charge("resolved direct file edge")
        val observer = modulesById[edge.observingModuleId]
            ?: headerPlanFail("direct edge names an unknown observing module")
        requireCanonicalPlanPath(edge.consumerPath, "direct-edge consumer")
        requireSourcePath(edge.dependencyHeaderPath, HEADER_PLAN_HEADER_SUFFIXES, "direct-edge dependency")
        if (edge.consumerPath in sourceOnlyPaths) {
            headerPlanFail("source-only units cannot own or contribute module-graph edges")
        }
        val consumerId = nodeIdByPath[edge.consumerPath]
            ?: headerPlanFail("direct edge names an unknown consumer")
        val dependencyId = headerIds[edge.dependencyHeaderPath]
            ?: headerPlanFail("direct edge names an unknown canonical header dependency")
        if (consumerId in moduleIds && consumerId != observer.moduleId) {
            headerPlanFail("direct edge module consumer is not its observing module")
        }
        if (observer.moduleId to dependencyId !in observedHeaders ||
            (consumerId in headerOwnerIds && observer.moduleId to consumerId !in observedHeaders)
        ) {
            headerPlanFail("direct edge lacks exact per-TU header observation evidence")
        }
        val identity = "${observer.moduleId}\u0000$consumerId\u0000$dependencyId"
        if (!identities.add(identity)) headerPlanFail("resolved direct file edges contain a duplicate")
        result += ValidatedDirectEdge(
            observer.moduleId,
            observer.shardId,
            edge.consumerPath,
            edge.dependencyHeaderPath,
            consumerId,
            dependencyId,
        )
    }
    return result.sortedWith { left, right ->
        FULL_TREE_CODE_POINT_ORDER.compare(left.observingModuleId, right.observingModuleId).takeIf { it != 0 }
            ?: FULL_TREE_CODE_POINT_ORDER.compare(left.consumerNodeId, right.consumerNodeId).takeIf { it != 0 }
            ?: FULL_TREE_CODE_POINT_ORDER.compare(left.dependencyNodeId, right.dependencyNodeId)
    }
}

private fun validateBlockers(
    raw: List<FullTreeHeaderResolutionBlocker>,
    modules: List<ValidatedModule>,
    headers: List<ValidatedHeader>,
    nodeIdByPath: Map<String, String>,
    sourceOnlyPaths: Set<String>,
    work: HeaderPlanWorkBudget,
): List<ValidatedBlocker> {
    val knownConsumerPaths = modules.mapTo(HashSet<String>(), ValidatedModule::sourcePath).apply {
        addAll(headers.map(ValidatedHeader::sourcePath))
    }
    val byId = TreeMap<String, ValidatedBlocker>(FULL_TREE_CODE_POINT_ORDER)
    raw.forEach { blocker ->
        work.charge("resolution blocker")
        requireCanonicalPlanPath(blocker.consumerPath, "resolution-blocker consumer")
        if (blocker.consumerPath in sourceOnlyPaths) {
            headerPlanFail("source-only units cannot own resolution blockers")
        }
        if (blocker.consumerPath !in knownConsumerPaths) {
            headerPlanFail("resolution blocker names an unknown consumer")
        }
        if (!HEADER_PLAN_SHA256.matches(blocker.evidenceSha256)) {
            headerPlanFail("resolution blocker evidence is not a full lowercase SHA-256")
        }
        val blockerId = fullDomainId(
            "blocker",
            HEADER_PLAN_BLOCKER_ID_DOMAIN,
            listOf(blocker.consumerPath, blocker.kind.wireName, blocker.evidenceSha256),
        )
        val validated = ValidatedBlocker(
            blockerId,
            blocker.consumerPath,
            nodeIdByPath.getValue(blocker.consumerPath),
            blocker.kind,
            blocker.evidenceSha256,
        )
        if (byId.putIfAbsent(blockerId, validated) != null) {
            headerPlanFail("resolution blockers contain a duplicate identity")
        }
    }
    return Collections.unmodifiableList(byId.values.toList())
}

private fun requireExactBlockerAccounting(
    modules: List<ValidatedModule>,
    headers: List<ValidatedHeader>,
    blockers: List<ValidatedBlocker>,
) {
    val actual = blockers.groupingBy(ValidatedBlocker::consumerPath).eachCount()
    modules.forEach { module ->
        if (actual.getOrDefault(module.sourcePath, 0) != module.unresolvedBlockerCount) {
            headerPlanFail("planning module unresolved-blocker accounting differs from its typed records")
        }
    }
    headers.forEach { header ->
        if (actual.getOrDefault(header.sourcePath, 0) != header.unresolvedBlockerCount) {
            headerPlanFail("canonical header unresolved-blocker accounting differs from its typed records")
        }
    }
}

private fun emptyAdjacency(nodeIds: Set<String>): TreeMap<String, TreeSet<String>> =
    TreeMap<String, TreeSet<String>>(FULL_TREE_CODE_POINT_ORDER).apply {
        nodeIds.forEach { put(it, TreeSet(FULL_TREE_CODE_POINT_ORDER)) }
    }

private fun buildCondensationGraph(
    nodes: Map<String, HeaderPlanNode>,
    adjacency: Map<String, Set<String>>,
    reverseAdjacency: Map<String, Set<String>>,
    limits: FullTreeHeaderModulePlanLimits,
    work: HeaderPlanWorkBudget,
): HeaderPlanGraph {
    val finishOrder = deterministicFinishOrder(nodes.keys, adjacency, work)
    val componentMembers = deterministicComponents(finishOrder, reverseAdjacency, work)
    val nodeToComponent = HashMap<String, String>(nodes.size)
    val componentsById = TreeMap<String, HeaderPlanComponent>(FULL_TREE_CODE_POINT_ORDER)
    componentMembers.forEach { rawMembers ->
        val members = rawMembers.sortedWith(FULL_TREE_CODE_POINT_ORDER)
        work.charge(members.size.toLong() + 1L, "SCC component")
        val componentId = fullDomainId("scc", HEADER_PLAN_SCC_ID_DOMAIN, members)
        val component = HeaderPlanComponent(
            componentId = componentId,
            memberNodeIds = Collections.unmodifiableList(members),
            moduleIds = Collections.unmodifiableList(
                members.filter { nodes.getValue(it).kind == HeaderPlanNodeKind.MODULE },
            ),
            headerOwnerIds = Collections.unmodifiableList(
                members.filter { nodes.getValue(it).kind == HeaderPlanNodeKind.HEADER },
            ),
        )
        if (componentsById.putIfAbsent(componentId, component) != null) {
            headerPlanFail("SCC component IDs collided")
        }
        members.forEach { member ->
            if (nodeToComponent.putIfAbsent(member, componentId) != null) {
                headerPlanFail("graph node belongs to more than one SCC component")
            }
        }
    }
    if (nodeToComponent.size != nodes.size) headerPlanFail("SCC condensation omitted a graph node")

    val outgoing = TreeMap<String, TreeSet<String>>(FULL_TREE_CODE_POINT_ORDER).apply {
        componentsById.keys.forEach { put(it, TreeSet(FULL_TREE_CODE_POINT_ORDER)) }
    }
    adjacency.forEach { (consumerNode, dependencies) ->
        val consumerComponent = nodeToComponent.getValue(consumerNode)
        dependencies.forEach { dependencyNode ->
            work.charge("condensation candidate edge")
            val dependencyComponent = nodeToComponent.getValue(dependencyNode)
            if (consumerComponent != dependencyComponent) {
                outgoing.getValue(dependencyComponent).add(consumerComponent)
            }
        }
    }
    val edgeCount = outgoing.values.sumOf { it.size }
    if (edgeCount > limits.maximumCondensationEdges) {
        headerPlanFail("header module plan exceeds its condensation-edge bound")
    }
    val edges = ArrayList<HeaderPlanCondensationEdge>(edgeCount)
    outgoing.forEach { (dependency, consumers) ->
        consumers.forEach { consumer ->
            work.charge("condensation edge")
            edges += HeaderPlanCondensationEdge(dependency, consumer)
        }
    }
    val kahnOrder = deterministicKahnOrder(componentsById.keys, outgoing, work)
    return HeaderPlanGraph(
        components = Collections.unmodifiableList(componentsById.values.toList()),
        edges = Collections.unmodifiableList(edges),
        kahnOrder = Collections.unmodifiableList(kahnOrder),
    )
}

private class HeaderPlanDfsFrame(
    val nodeId: String,
    val dependencies: List<String>,
    var nextIndex: Int = 0,
)

private fun deterministicFinishOrder(
    nodeIds: Set<String>,
    adjacency: Map<String, Set<String>>,
    work: HeaderPlanWorkBudget,
): List<String> {
    val visited = HashSet<String>(nodeIds.size)
    val finished = ArrayList<String>(nodeIds.size)
    nodeIds.sortedWith(FULL_TREE_CODE_POINT_ORDER).forEach { start ->
        if (!visited.add(start)) return@forEach
        work.charge("SCC forward node")
        val stack = ArrayDeque<HeaderPlanDfsFrame>()
        stack.addLast(HeaderPlanDfsFrame(start, adjacency.getValue(start).toList()))
        while (stack.isNotEmpty()) {
            val frame = stack.peekLast()
            if (frame.nextIndex < frame.dependencies.size) {
                val dependency = frame.dependencies[frame.nextIndex++]
                work.charge("SCC forward edge")
                if (visited.add(dependency)) {
                    work.charge("SCC forward node")
                    stack.addLast(
                        HeaderPlanDfsFrame(dependency, adjacency.getValue(dependency).toList()),
                    )
                }
            } else {
                stack.removeLast()
                finished += frame.nodeId
            }
        }
    }
    return finished
}

private fun deterministicComponents(
    finishOrder: List<String>,
    reverseAdjacency: Map<String, Set<String>>,
    work: HeaderPlanWorkBudget,
): List<List<String>> {
    val assigned = HashSet<String>(finishOrder.size)
    val components = ArrayList<List<String>>()
    finishOrder.asReversed().forEach { start ->
        if (!assigned.add(start)) return@forEach
        val members = ArrayList<String>()
        val stack = ArrayDeque<String>()
        stack.addLast(start)
        while (stack.isNotEmpty()) {
            val node = stack.removeLast()
            work.charge("SCC reverse node")
            members += node
            reverseAdjacency.getValue(node).toList().asReversed().forEach { consumer ->
                work.charge("SCC reverse edge")
                if (assigned.add(consumer)) stack.addLast(consumer)
            }
        }
        components += members
    }
    return components
}

private fun deterministicKahnOrder(
    componentIds: Set<String>,
    outgoing: Map<String, Set<String>>,
    work: HeaderPlanWorkBudget,
): List<String> {
    val indegree = TreeMap<String, Int>(FULL_TREE_CODE_POINT_ORDER).apply {
        componentIds.forEach { put(it, 0) }
    }
    outgoing.values.forEach { consumers ->
        consumers.forEach { consumer ->
            work.charge("Kahn indegree edge")
            indegree[consumer] = Math.addExact(indegree.getValue(consumer), 1)
        }
    }
    val ready = PriorityQueue(FULL_TREE_CODE_POINT_ORDER)
    indegree.forEach { (component, degree) -> if (degree == 0) ready.add(component) }
    val order = ArrayList<String>(componentIds.size)
    while (ready.isNotEmpty()) {
        val dependency = ready.remove()
        work.charge("Kahn component")
        order += dependency
        outgoing.getValue(dependency).forEach { consumer ->
            work.charge("Kahn edge")
            val remaining = Math.subtractExact(indegree.getValue(consumer), 1)
            indegree[consumer] = remaining
            if (remaining == 0) ready.add(consumer)
        }
    }
    if (order.size != componentIds.size) headerPlanFail("SCC condensation graph is cyclic")
    return order
}

/**
 * Retains exact per-TU A13 shard observations without inferring use through the union/may graph.
 * A shared header keeps its own first-class owner; component facts are only unions of the exact
 * observations of their members and never transitive reachability claims.
 */
private fun buildHeaderPlanBoundaries(
    nodes: Map<String, HeaderPlanNode>,
    headerObservations: List<ValidatedHeaderObservation>,
    graph: HeaderPlanGraph,
    work: HeaderPlanWorkBudget,
): HeaderPlanBoundaryFacts {
    val assignedNodeIds = HashSet<String>(nodes.size)
    val memberShards = TreeMap<String, TreeSet<String>>(FULL_TREE_CODE_POINT_ORDER)
    val nodeConsumerShards = TreeMap<String, TreeSet<String>>(FULL_TREE_CODE_POINT_ORDER)
    graph.components.forEach { component ->
        val shards = TreeSet<String>(FULL_TREE_CODE_POINT_ORDER)
        component.memberNodeIds.forEach { nodeId ->
            work.charge("component boundary member")
            if (!assignedNodeIds.add(nodeId)) {
                headerPlanFail("boundary construction found duplicate component membership")
            }
            val nodeShards = TreeSet<String>(FULL_TREE_CODE_POINT_ORDER)
            nodes.getValue(nodeId).shardId?.let { shardId ->
                work.charge("module boundary shard membership")
                shards.add(shardId)
                nodeShards.add(shardId)
            }
            nodeConsumerShards[nodeId] = nodeShards
        }
        memberShards[component.componentId] = shards
    }
    if (assignedNodeIds.size != nodes.size) {
        headerPlanFail("boundary construction omitted a graph node")
    }
    headerObservations.forEach { observation ->
        work.charge("exact header consumer-shard membership")
        nodeConsumerShards.getValue(observation.headerOwnerId).add(observation.observingShardId)
    }

    val componentConsumerShards = TreeMap<String, TreeSet<String>>(FULL_TREE_CODE_POINT_ORDER)
    graph.components.forEach { component ->
        val shards = TreeSet<String>(FULL_TREE_CODE_POINT_ORDER)
        component.memberNodeIds.forEach { nodeId ->
            nodeConsumerShards.getValue(nodeId).forEach { shardId ->
                work.charge("component exact consumer-shard membership")
                shards.add(shardId)
            }
        }
        componentConsumerShards[component.componentId] = shards
    }

    val headerShards = TreeMap<String, List<String>>(FULL_TREE_CODE_POINT_ORDER)
    nodes.values.filter { it.kind == HeaderPlanNodeKind.HEADER }.forEach { header ->
        work.charge("header consumer boundary")
        val exactShards = nodeConsumerShards.getValue(header.nodeId)
        work.charge(exactShards.size.toLong(), "header consumer-shard output membership")
        headerShards[header.nodeId] = immutableHeaderPlanList(exactShards)
    }
    return HeaderPlanBoundaryFacts(
        componentMemberShardIds = immutableHeaderPlanMap(memberShards.mapValues { (_, value) ->
            work.charge(value.size.toLong(), "component member-shard output membership")
            immutableHeaderPlanList(value)
        }),
        componentConsumerShardIds = immutableHeaderPlanMap(componentConsumerShards.mapValues { (_, value) ->
            work.charge(value.size.toLong(), "component consumer-shard output membership")
            immutableHeaderPlanList(value)
        }),
        headerConsumerShardIds = immutableHeaderPlanMap(headerShards),
    )
}

private fun renderHeaderModulePlan(
    modules: List<ValidatedModule>,
    headers: List<ValidatedHeader>,
    sourceOnly: List<ValidatedSourceOnly>,
    headerObservations: List<ValidatedHeaderObservation>,
    directEdges: List<ValidatedDirectEdge>,
    blockers: List<ValidatedBlocker>,
    graph: HeaderPlanGraph,
    boundaries: HeaderPlanBoundaryFacts,
    complete: Boolean,
    isolatedModules: Int,
    workUnits: Long,
    limits: FullTreeHeaderModulePlanLimits,
): JsonObject = JsonObject(
    mapOf(
        "authority" to JsonPrimitive("fixture-resolved-non-authoritative"),
        "blockers" to JsonArray(blockers.map { blocker ->
            JsonObject(
                mapOf(
                    "blockerId" to JsonPrimitive(blocker.blockerId),
                    "consumerNodeId" to JsonPrimitive(blocker.consumerNodeId),
                    "consumerPath" to JsonPrimitive(blocker.consumerPath),
                    "evidenceSha256" to JsonPrimitive(blocker.evidenceSha256),
                    "kind" to JsonPrimitive(blocker.kind.wireName),
                ),
            )
        }),
        "complete" to JsonPrimitive(complete),
        "condensationDag" to JsonObject(
            mapOf(
                "complete" to JsonPrimitive(complete),
                "components" to JsonArray(graph.components.map { component ->
                    JsonObject(
                        mapOf(
                            "componentId" to JsonPrimitive(component.componentId),
                            "consumerShardIds" to JsonArray(
                                boundaries.componentConsumerShardIds.getValue(component.componentId)
                                    .map(::JsonPrimitive),
                            ),
                            "crossShardConsumer" to JsonPrimitive(
                                boundaries.componentConsumerShardIds.getValue(component.componentId).size > 1,
                            ),
                            "headerOwnerIds" to JsonArray(component.headerOwnerIds.map(::JsonPrimitive)),
                            "memberNodeIds" to JsonArray(component.memberNodeIds.map(::JsonPrimitive)),
                            "memberShardIds" to JsonArray(
                                boundaries.componentMemberShardIds.getValue(component.componentId)
                                    .map(::JsonPrimitive),
                            ),
                            "moduleIds" to JsonArray(component.moduleIds.map(::JsonPrimitive)),
                        ),
                    )
                }),
                "edgeDirection" to JsonPrimitive("dependency-component-before-consumer-component"),
                "edges" to JsonArray(graph.edges.map { edge ->
                    JsonObject(
                        mapOf(
                            "consumerComponentId" to JsonPrimitive(edge.consumerComponentId),
                            "dependencyComponentId" to JsonPrimitive(edge.dependencyComponentId),
                        ),
                    )
                }),
                "kahnOrder" to JsonArray(graph.kahnOrder.map(::JsonPrimitive)),
                "graphSemantics" to JsonPrimitive("union-may-graph-across-contextual-per-tu-direct-edges"),
                "ordering" to JsonPrimitive("unicode-code-point-id-with-code-point-priority-kahn"),
            ),
        ),
        "counts" to JsonObject(
            mapOf(
                "canonicalHeaders" to JsonPrimitive(headers.size),
                "condensationComponents" to JsonPrimitive(graph.components.size),
                "condensationEdges" to JsonPrimitive(graph.edges.size),
                "crossShardConsumerComponents" to JsonPrimitive(
                    boundaries.componentConsumerShardIds.values.count { it.size > 1 },
                ),
                "directFileEdges" to JsonPrimitive(directEdges.size),
                "graphNodes" to JsonPrimitive(modules.size + headers.size),
                "headerObservations" to JsonPrimitive(headerObservations.size),
                "isolatedModules" to JsonPrimitive(isolatedModules),
                "planningModules" to JsonPrimitive(modules.size),
                "resolutionBlockers" to JsonPrimitive(blockers.size),
                "sourceOnlyUnits" to JsonPrimitive(sourceOnly.size),
                "sharedAcrossShardsHeaders" to JsonPrimitive(
                    boundaries.headerConsumerShardIds.values.count { it.size > 1 },
                ),
                "unreferencedHeaders" to JsonPrimitive(
                    boundaries.headerConsumerShardIds.values.count(List<String>::isEmpty),
                ),
                "workUnits" to JsonPrimitive(workUnits),
            ),
        ),
        "directFileEdges" to JsonArray(directEdges.map { edge ->
            JsonObject(
                mapOf(
                    "consumerNodeId" to JsonPrimitive(edge.consumerNodeId),
                    "consumerPath" to JsonPrimitive(edge.consumerPath),
                    "dependencyHeaderOwnerId" to JsonPrimitive(edge.dependencyNodeId),
                    "dependencyHeaderPath" to JsonPrimitive(edge.dependencyHeaderPath),
                    "observingModuleId" to JsonPrimitive(edge.observingModuleId),
                    "observingShardId" to JsonPrimitive(edge.observingShardId),
                ),
            )
        }),
        "effectiveLimits" to JsonObject(
            mapOf(
                "maximumBlockers" to JsonPrimitive(limits.maximumBlockers),
                "maximumCondensationEdges" to JsonPrimitive(limits.maximumCondensationEdges),
                "maximumDirectEdges" to JsonPrimitive(limits.maximumDirectEdges),
                "maximumGraphNodes" to JsonPrimitive(limits.maximumGraphNodes),
                "maximumHeaderObservations" to JsonPrimitive(limits.maximumHeaderObservations),
                "maximumHeaders" to JsonPrimitive(limits.maximumHeaders),
                "maximumModules" to JsonPrimitive(limits.maximumModules),
                "maximumSerializedBytes" to JsonPrimitive(limits.maximumSerializedBytes),
                "maximumSourceOnlyUnits" to JsonPrimitive(limits.maximumSourceOnlyUnits),
                "maximumWorkUnits" to JsonPrimitive(limits.maximumWorkUnits),
            ),
        ),
        "headerOwners" to JsonArray(headers.map { header ->
            JsonObject(
                mapOf(
                    "graphNodeId" to JsonPrimitive(header.headerOwnerId),
                    "headerOwnerId" to JsonPrimitive(header.headerOwnerId),
                    "consumerShardIds" to JsonArray(
                        boundaries.headerConsumerShardIds.getValue(header.headerOwnerId).map(::JsonPrimitive),
                    ),
                    "ownerKind" to JsonPrimitive("canonical-header-first-class-sha256"),
                    "sourcePath" to JsonPrimitive(header.sourcePath),
                    "unresolvedBlockerCount" to JsonPrimitive(header.unresolvedBlockerCount),
                ),
            )
        }),
        "headerObservations" to JsonArray(headerObservations.map { observation ->
            JsonObject(
                mapOf(
                    "headerOwnerId" to JsonPrimitive(observation.headerOwnerId),
                    "headerPath" to JsonPrimitive(observation.headerPath),
                    "observingModuleId" to JsonPrimitive(observation.observingModuleId),
                    "observingShardId" to JsonPrimitive(observation.observingShardId),
                ),
            )
        }),
        "kind" to JsonPrimitive("full-tree-header-module-plan-fixture-v2"),
        "modules" to JsonArray(modules.map { module ->
            JsonObject(
                mapOf(
                    "graphNodeId" to JsonPrimitive(module.moduleId),
                    "moduleId" to JsonPrimitive(module.moduleId),
                    "shardId" to JsonPrimitive(module.shardId),
                    "sourcePath" to JsonPrimitive(module.sourcePath),
                    "unresolvedBlockerCount" to JsonPrimitive(module.unresolvedBlockerCount),
                ),
            )
        }),
        "resolutionPolicy" to JsonObject(
            mapOf(
                "directEdges" to JsonPrimitive("fully-compiler-resolved-file-identities-only"),
                "headerOwnership" to JsonPrimitive("full-domain-sha256-of-canonical-header-path"),
                "headerSubsystemBoundary" to JsonPrimitive(
                    "exact-per-tu-observing-module-shard-set-without-transitive-inference",
                ),
                "sourceOnlyOwnership" to JsonPrimitive("forbidden"),
                "unresolvedEvidence" to JsonPrimitive("exact-count-accounted-blockers-only"),
            ),
        ),
        "schemaVersion" to JsonPrimitive(2),
        "sourceOnlyUnits" to JsonArray(sourceOnly.map { unit ->
            JsonObject(
                mapOf(
                    "ownershipStatus" to JsonPrimitive("excluded-non-owning"),
                    "shardId" to JsonPrimitive(unit.shardId),
                    "sourcePath" to JsonPrimitive(unit.sourcePath),
                ),
            )
        }),
        "status" to JsonPrimitive(if (complete) "complete" else "incomplete-accounted-blockers"),
    ),
)

private fun requireBlockerCount(
    count: Int,
    limits: FullTreeHeaderModulePlanLimits,
    label: String,
) {
    if (count < 0 || count > limits.maximumBlockers) {
        headerPlanFail("$label unresolved-blocker count is outside its bound")
    }
}

private fun requireShardId(value: String, label: String) {
    if (!HEADER_PLAN_SHARD_ID.matches(value) || value in HEADER_PLAN_CATCH_ALL_IDS) {
        headerPlanFail("$label shard ID is malformed or a forbidden catch-all")
    }
}

private fun requireSourcePath(path: String, suffixes: Set<String>, label: String) {
    requireCanonicalPlanPath(path, label)
    if (suffixes.none(path::endsWith)) headerPlanFail("$label has an unsupported file suffix")
}

private fun requireCanonicalPlanPath(path: String, label: String) {
    if (path.length > HEADER_PLAN_MAXIMUM_PATH_BYTES || path.isEmpty() || path.startsWith('/') ||
        '\\' in path || path.any { it.code !in 0x20..0x7e } ||
        !(path.startsWith("source/") || path.startsWith("generated/")) ||
        path.split('/').any { it.isEmpty() || it == "." || it == ".." }
    ) {
        headerPlanFail("$label path is not a canonical bounded source/generated path")
    }
}

private fun headerOwnerId(path: String): String =
    fullDomainId("header", HEADER_PLAN_HEADER_ID_DOMAIN, listOf(path))

private fun fullDomainId(prefix: String, domain: String, fields: List<String>): String {
    val digest = MessageDigest.getInstance("SHA-256")
    digest.updateFramed(domain)
    digest.updateUnsignedInt(fields.size)
    fields.forEach(digest::updateFramed)
    val hexadecimal = digest.digest().joinToString("") { byte ->
        (byte.toInt() and 0xff).toString(16).padStart(2, '0')
    }
    return "$prefix-$hexadecimal"
}

private fun MessageDigest.updateFramed(value: String) {
    val bytes = value.toByteArray(StandardCharsets.UTF_8)
    updateUnsignedInt(bytes.size)
    update(bytes)
}

private fun MessageDigest.updateUnsignedInt(value: Int) {
    if (value < 0) headerPlanFail("negative value cannot enter a hash frame")
    update(
        byteArrayOf(
            (value ushr 24).toByte(),
            (value ushr 16).toByte(),
            (value ushr 8).toByte(),
            value.toByte(),
        ),
    )
}

private fun canonicalHeaderPlanBytes(
    document: JsonObject,
    limits: FullTreeHeaderModulePlanLimits,
): ByteArray = try {
    OracleJson.canonicalBytes(
        document,
        StrictJsonLimits(
            maximumInputBytes = limits.maximumSerializedBytes,
            maximumCanonicalBytes = limits.maximumSerializedBytes,
            maximumDepth = 32,
            maximumNodes = 1_000_000,
            maximumStringBytes = minOf(16 * 1024, limits.maximumSerializedBytes),
            maximumTotalStringBytes = limits.maximumSerializedBytes,
            maximumNumberCharacters = 64,
        ),
    )
} catch (failure: FullTreeHeaderModulePlanException) {
    throw failure
} catch (failure: Exception) {
    throw FullTreeHeaderModulePlanException("header module plan exceeds its canonical JSON bounds", failure)
}

private fun <T> immutableHeaderPlanList(values: Collection<T>): List<T> =
    Collections.unmodifiableList(ArrayList(values))

private fun <T> immutableHeaderPlanMap(values: Map<String, T>): Map<String, T> =
    Collections.unmodifiableMap(TreeMap<String, T>(FULL_TREE_CODE_POINT_ORDER).apply { putAll(values) })

private class HeaderPlanWorkBudget(private val maximum: Long) {
    var used: Long = 0L
        private set

    fun charge(label: String) = charge(1L, label)

    fun charge(amount: Long, label: String) {
        if (amount < 0L) headerPlanFail("negative $label work charge")
        used = try {
            Math.addExact(used, amount)
        } catch (failure: ArithmeticException) {
            throw FullTreeHeaderModulePlanException("header module plan work count overflowed", failure)
        }
        if (used > maximum) headerPlanFail("header module plan exceeds its work-unit bound during $label")
    }
}

private fun headerPlanFail(message: String): Nothing = throw FullTreeHeaderModulePlanException(message)

private val HEADER_PLAN_MODULE_ID = Regex("cu-[0-9a-f]{32}")
private val HEADER_PLAN_SHARD_ID = Regex("[a-z0-9][a-z0-9-]{0,127}")
private val HEADER_PLAN_SHA256 = Regex("[0-9a-f]{64}")
private val HEADER_PLAN_MODULE_SUFFIXES = setOf(".c", ".cc", ".cpp", ".cxx", ".m", ".mm")
private val HEADER_PLAN_HEADER_SUFFIXES = setOf(".def", ".h", ".hh", ".hpp", ".hxx", ".inc")
private val HEADER_PLAN_CATCH_ALL_IDS = setOf("catch-all", "catchall", "core", "default", "misc", "unowned")

private const val HEADER_PLAN_HEADER_ID_DOMAIN = "decomp-full-tree-header-owner-v1-length-framed-utf8"
private const val HEADER_PLAN_BLOCKER_ID_DOMAIN = "decomp-full-tree-header-blocker-v1-length-framed-utf8"
private const val HEADER_PLAN_SCC_ID_DOMAIN = "decomp-full-tree-header-scc-v1-length-framed-utf8"
private const val HEADER_PLAN_MAXIMUM_PATH_BYTES = 4096
internal const val HEADER_PLAN_MAXIMUM_MODULES = 10_000
internal const val HEADER_PLAN_MAXIMUM_HEADERS = 50_000
internal const val HEADER_PLAN_MAXIMUM_SOURCE_ONLY_UNITS = 50_000
internal const val HEADER_PLAN_MAXIMUM_HEADER_OBSERVATIONS = 100_000
internal const val HEADER_PLAN_MAXIMUM_DIRECT_EDGES = 100_000
internal const val HEADER_PLAN_MAXIMUM_BLOCKERS = 50_000
internal const val HEADER_PLAN_MAXIMUM_GRAPH_NODES = 60_000
internal const val HEADER_PLAN_MAXIMUM_CONDENSATION_EDGES = 100_000
internal const val HEADER_PLAN_MAXIMUM_WORK_UNITS = 5_000_000L
internal const val HEADER_PLAN_MAXIMUM_SERIALIZED_BYTES = 64 * 1024 * 1024
