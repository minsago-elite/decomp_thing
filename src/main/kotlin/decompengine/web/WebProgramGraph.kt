package decompengine.web

/**
 * Recorded relationships of one structure projection, as compressed adjacency built once per projection.
 *
 * Call edges are exactly the program model's `functions[].calls`, one edge per distinct caller and target with
 * the recorded occurrence count. A target with no model record stays an explicit unrecorded endpoint. Module
 * edges are derived from those calls and `functions[].referencedGlobals` through the recorded plan ownership,
 * the rule the planner uses for module dependencies; a reference whose target has no single owning module is
 * counted as unattributed instead of being assigned to a module.
 */
internal class WebProgramGraph private constructor(
    /** Nodes `0 until recorded` are recorded rows (functions or modules); the rest are unrecorded call targets. */
    val nodes: Int,
    val recorded: Int,
    val unrecordedIds: Array<String>,
    private val outOffsets: IntArray,
    private val edgeSources: IntArray,
    private val edgeTargets: IntArray,
    private val edgeReferences: IntArray,
    private val edgeRelationships: ByteArray,
    private val inOffsets: IntArray,
    private val inEdgeList: IntArray,
    /** Module graph only: references from each module whose target has no single owning module or no record. */
    val unattributed: IntArray,
) {
    val edges: Int get() = edgeTargets.size

    fun outEdges(node: Int): IntRange = outOffsets[node] until outOffsets[node + 1]
    fun outDegree(node: Int): Int = outOffsets[node + 1] - outOffsets[node]
    fun inDegree(node: Int): Int = inOffsets[node + 1] - inOffsets[node]
    /** Positions of the edges entering [node]; [inEdge] maps a position to its edge number. */
    fun inPositions(node: Int): IntRange = inOffsets[node] until inOffsets[node + 1]
    fun inEdge(position: Int): Int = inEdgeList[position]
    fun source(edge: Int): Int = edgeSources[edge]
    fun target(edge: Int): Int = edgeTargets[edge]
    fun references(edge: Int): Int = edgeReferences[edge]
    fun relationship(edge: Int): Relationship = Relationship.entries[edgeRelationships[edge].toInt()]

    enum class Relationship(val wire: String) { CALL("call"), MODULE_CALL("module-call"), MODULE_GLOBAL("module-global-reference") }

    companion object {
        /**
         * Compressed adjacency from per-node edge keys (`target shl 8 or relationship`), duplicates allowed:
         * each distinct key becomes one edge carrying its occurrence count, ordered by target and relationship.
         */
        private fun build(nodes: Int, recorded: Int, unrecorded: Array<String>, unattributed: IntArray,
            keys: (Int) -> LongArray): WebProgramGraph {
            val outOffsets = IntArray(nodes + 1)
            val rows = arrayOfNulls<LongArray>(nodes)
            for (node in 0 until nodes) {
                val row = keys(node).also { it.sort() }
                rows[node] = row
                var distinct = 0
                for (position in row.indices) if (position == 0 || row[position] != row[position - 1]) distinct++
                outOffsets[node + 1] = outOffsets[node] + distinct
            }
            val total = outOffsets[nodes]
            val sources = IntArray(total); val targets = IntArray(total); val references = IntArray(total)
            val relationships = ByteArray(total)
            val inOffsets = IntArray(nodes + 1)
            for (node in 0 until nodes) {
                val row = checkNotNull(rows[node])
                var edge = outOffsets[node] - 1
                for (position in row.indices) {
                    if (position == 0 || row[position] != row[position - 1]) {
                        edge++
                        val target = (row[position] ushr 8).toInt()
                        sources[edge] = node; targets[edge] = target; relationships[edge] = (row[position] and 0xff).toByte()
                        inOffsets[target + 1]++
                    }
                    references[edge]++
                }
                rows[node] = null
            }
            for (node in 0 until nodes) inOffsets[node + 1] += inOffsets[node]
            val inEdges = IntArray(total)
            val cursor = inOffsets.copyOf(nodes)
            for (edge in 0 until total) inEdges[cursor[targets[edge]]++] = edge
            return WebProgramGraph(nodes, recorded, unrecorded, outOffsets, sources, targets, references, relationships,
                inOffsets, inEdges, unattributed)
        }

        private fun key(target: Int, relationship: Relationship): Long = (target.toLong() shl 8) or relationship.ordinal.toLong()

        /** Function call graph. Unrecorded targets become nodes after the recorded rows, in first-recorded order. */
        fun calls(index: WebProgramStructureIndex): WebProgramGraph {
            val functions = index.table(WebStructureKind.FUNCTION)
            val unrecorded = LinkedHashMap<String, Int>()
            for (row in 0 until functions.size) for (target in functions.calls[row]) {
                if (target !in functions.index && target !in unrecorded) unrecorded[target] = functions.size + unrecorded.size
            }
            return build(functions.size + unrecorded.size, functions.size, unrecorded.keys.toTypedArray(), IntArray(0)) { node ->
                if (node >= functions.size) LongArray(0)
                else functions.calls[node].let { calls -> LongArray(calls.size) {
                    key(functions.index[calls[it]] ?: unrecorded.getValue(calls[it]), Relationship.CALL)
                } }
            }
        }

        /** Module dependency graph derived from recorded calls and global references through plan ownership. */
        fun modules(index: WebProgramStructureIndex): WebProgramGraph {
            val functions = index.table(WebStructureKind.FUNCTION)
            val globals = index.table(WebStructureKind.GLOBAL)
            val rows = Array(index.modules.size) { LongList() }
            val unattributed = IntArray(index.modules.size)
            fun attribute(owner: Int, targets: Array<String>, table: WebStructureTable, relationship: Relationship) {
                for (target in targets) {
                    val targetOwner = table.index[target]?.let { table.owners[it] } ?: OWNER_UNOWNED
                    if (targetOwner < 0) unattributed[owner]++
                    else if (targetOwner != owner) rows[owner].add(key(targetOwner, relationship))
                }
            }
            for (row in 0 until functions.size) {
                val owner = functions.owners[row]
                if (owner < 0) continue
                attribute(owner, functions.calls[row], functions, Relationship.MODULE_CALL)
                attribute(owner, functions.referencedGlobals[row], globals, Relationship.MODULE_GLOBAL)
            }
            return build(index.modules.size, index.modules.size, emptyArray(), unattributed) { rows[it].toArray() }
        }
    }

    private class LongList {
        private var values = LongArray(4)
        private var size = 0
        fun add(value: Long) { if (size == values.size) values = values.copyOf(size * 2); values[size++] = value }
        fun toArray(): LongArray = values.copyOf(size)
    }
}

/**
 * A bounded neighborhood: included nodes in discovery order (the focus first), their distances, and the
 * included edges among them. Totals are exact unless the exploration bound was reached, when they are null.
 */
internal class WebGraphNeighborhood(
    val nodes: IntArray,
    val depths: IntArray,
    val edges: IntArray,
    val reachableNodes: Int?,
    val reachableEdges: Int?,
    val edgesBeyondDepth: Int?,
    val filteredEdges: Int?,
    val reasons: List<String>,
) {
    companion object {
        /** Exploration bound in adjacency visits; past it, reachable totals are unknown rather than guessed. */
        const val MAXIMUM_VISITS = 1_000_000

        /**
         * Breadth-first neighborhood of [focus] within [depth] steps along the allowed directions, over nodes
         * admitted by [admit]. The reachable set and the edges among it are counted exactly within
         * [maximumVisits]; the first [nodeLimit] nodes in discovery order and the first [edgeLimit] edges among
         * those nodes, nearest first, are returned.
         */
        fun of(graph: WebProgramGraph, focus: Int, depth: Int, outgoing: Boolean, incoming: Boolean,
            nodeLimit: Int, edgeLimit: Int, admit: (Int) -> Boolean = { true },
            maximumVisits: Int = MAXIMUM_VISITS): WebGraphNeighborhood {
            require(outgoing || incoming)
            val distance = HashMap<Int, Int>()
            val order = ArrayList<Int>()
            distance[focus] = 0; order += focus
            var visits = 0
            var exhausted = false
            fun reach(from: Int, node: Int) {
                if (node !in distance && admit(node)) { distance[node] = distance.getValue(from) + 1; order += node }
            }
            var head = 0
            explore@ while (head < order.size) {
                val node = order[head++]
                if (distance.getValue(node) >= depth) continue
                if (outgoing) for (edge in graph.outEdges(node)) {
                    if (++visits > maximumVisits) { exhausted = true; break@explore }
                    reach(node, graph.target(edge))
                }
                if (incoming) for (position in graph.inPositions(node)) {
                    if (++visits > maximumVisits) { exhausted = true; break@explore }
                    reach(node, graph.source(graph.inEdge(position)))
                }
            }
            // Edges among the reachable set (each from its source), edges that continue past the depth bound,
            // and edges to endpoints the filter excludes.
            var reachable = 0; var beyond = 0; var filtered = 0
            if (!exhausted) count@ for (node in order) {
                for (edge in graph.outEdges(node)) {
                    if (++visits > maximumVisits) { exhausted = true; break@count }
                    val target = graph.target(edge)
                    when {
                        target in distance -> reachable++
                        !admit(target) -> filtered++
                        outgoing -> beyond++
                    }
                }
                if (incoming) for (position in graph.inPositions(node)) {
                    if (++visits > maximumVisits) { exhausted = true; break@count }
                    if (graph.source(graph.inEdge(position)) !in distance) beyond++
                }
            }
            val included = order.subList(0, minOf(nodeLimit, order.size))
            val rank = HashMap<Int, Int>(included.size * 2).also { map -> included.forEachIndexed { position, node -> map[node] = position } }
            val candidates = ArrayList<Int>()
            for (node in included) for (edge in graph.outEdges(node)) if (graph.target(edge) in rank) candidates += edge
            // Edges among the nearest nodes come first, so a cut keeps the focus and its closest relationships.
            candidates.sortWith(compareBy<Int>({ maxOf(rank.getValue(graph.source(it)), rank.getValue(graph.target(it))) },
                { minOf(rank.getValue(graph.source(it)), rank.getValue(graph.target(it))) }, { it }))
            val edges = candidates.subList(0, minOf(edgeLimit, candidates.size)).toIntArray()
            val reasons = buildList {
                if (exhausted) add("VISIT_LIMIT")
                if (order.size > included.size) add("NODE_LIMIT")
                if (candidates.size > edges.size) add("EDGE_LIMIT")
            }
            return WebGraphNeighborhood(included.toIntArray(), IntArray(included.size) { distance.getValue(included[it]) }, edges,
                order.size.takeUnless { exhausted }, reachable.takeUnless { exhausted }, beyond.takeUnless { exhausted },
                filtered.takeUnless { exhausted }, reasons)
        }
    }
}
