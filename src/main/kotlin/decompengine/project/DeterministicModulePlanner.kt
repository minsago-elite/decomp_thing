package decompengine.project

import java.util.TreeSet

/**
 * Counts index entries and sparse-graph visits performed by one planner run.
 *
 * This is internal benchmark instrumentation rather than part of the archive schema. It lets the
 * scale regression tests distinguish work proportional to recovered evidence from an accidental
 * return to scanning every pair of functions.
 */
internal data class PlannerComplexity(
    val functionCount: Int,
    val globalCount: Int,
    val typeCount: Int,
    val indexedEvidenceEntries: Long,
    val affinityPostingVisits: Long,
    val anonymousGraphVisits: Long,
    val moduleGraphVisits: Long,
    val groupingIndexVisits: Long,
) {
    val sparseWorkUnits: Long
        get() = functionCount.toLong() + globalCount + typeCount + indexedEvidenceEntries + affinityPostingVisits +
            anonymousGraphVisits + moduleGraphVisits + groupingIndexVisits
}

internal data class IndexedPlannerRun(val plan: ModulePlan, val complexity: PlannerComplexity)

private class MutablePlannerComplexity(entityCount: Int, private val maximumWorkUnits: Long) {
    private var chargedWorkUnits = entityCount.toLong()

    init {
        require(chargedWorkUnits <= maximumWorkUnits) {
            "module planning requires $chargedWorkUnits entity work units; limit=$maximumWorkUnits"
        }
    }

    private fun charge(previous: Long, next: Long): Long {
        require(next >= previous && next - previous <= maximumWorkUnits - chargedWorkUnits) {
            "module planning exceeded its work limit during traversal; charged=$chargedWorkUnits, limit=$maximumWorkUnits"
        }
        chargedWorkUnits += next - previous
        return next
    }

    var indexedEvidenceEntries = 0L
        set(value) { field = charge(field, value) }
    var affinityPostingVisits = 0L
        set(value) { field = charge(field, value) }
    var anonymousGraphVisits = 0L
        set(value) { field = charge(field, value) }
    var moduleGraphVisits = 0L
        set(value) { field = charge(field, value) }
    var groupingIndexVisits = 0L
        set(value) { field = charge(field, value) }

    fun snapshot(functionCount: Int, globalCount: Int, typeCount: Int) = PlannerComplexity(
        functionCount = functionCount,
        globalCount = globalCount,
        typeCount = typeCount,
        indexedEvidenceEntries = indexedEvidenceEntries,
        affinityPostingVisits = affinityPostingVisits,
        anonymousGraphVisits = anonymousGraphVisits,
        moduleGraphVisits = moduleGraphVisits,
        groupingIndexVisits = groupingIndexVisits,
    )
}

private data class AffinityIndexes(
    val namedFunctions: List<RecoveredFunction>,
    val namedModules: List<String>,
    val namedIndexById: Map<String, Int>,
    val namedCallersByCallee: Map<String, List<Int>>,
    val namedFunctionsByGlobal: Map<String, List<Int>>,
    val namedFunctionsByString: Map<String, List<Int>>,
)

/** Deterministic ownership planning; LLM output is deliberately not allowed to choose paths. */
class DeterministicModulePlanner(
    private val maximumFunctionsPerModule: Int = 24,
    private val layout: ProjectLayoutProfile = GeneratedCMakeReconstructionProfile.descriptor.layout,
    private val maximumEntities: Int = Int.MAX_VALUE,
    private val maximumDependencyEdges: Long = Long.MAX_VALUE,
    private val maximumWorkUnits: Long = Long.MAX_VALUE,
) {
    init {
        require(maximumFunctionsPerModule > 0)
        require(maximumEntities > 0)
        require(maximumDependencyEdges > 0)
        require(maximumWorkUnits > 0)
    }

    fun plan(model: RecoveredProgramModel, overrides: Map<String, String> = emptyMap()): ModulePlan =
        planWithComplexity(model, overrides).plan

    internal fun planWithComplexity(
        model: RecoveredProgramModel,
        overrides: Map<String, String> = emptyMap(),
    ): IndexedPlannerRun {
        val entityCount = Math.addExact(Math.addExact(model.functions.size, model.globals.size), model.types.size)
        require(entityCount <= maximumEntities) {
            "module planning requires $entityCount entities; limit=$maximumEntities"
        }
        val complexity = MutablePlannerComplexity(entityCount, maximumWorkUnits)
        val dependencyEdges = model.functions.fold(0L) { total, function ->
            Math.addExact(total, Math.addExact(function.calls.size.toLong(), function.referencedGlobals.size.toLong()))
        }
        require(dependencyEdges <= maximumDependencyEdges) {
            "module planning requires $dependencyEdges dependency edges; limit=$maximumDependencyEdges"
        }
        val functions = model.functions.sortedWith(compareBy<RecoveredFunction> { it.address }.thenBy { it.id })
        val functionById = functions.associateBy { it.id }
        val globalIds = model.globals.mapTo(hashSetOf()) { it.id }
        val typeIds = model.types.mapTo(hashSetOf()) { it.id }
        require(overrides.keys.all { it in functionById || it in globalIds || it in typeIds }) {
            "module override references an unknown entity"
        }

        val intrinsicModuleByFunction = functions.associate { it.id to namedModule(it) }
        val affinityIndexes = buildAffinityIndexes(functions, intrinsicModuleByFunction, complexity)
        val anonymousComponents = anonymousComponents(functions, intrinsicModuleByFunction, complexity)
        val affinityScratch = AffinityScratch(affinityIndexes.namedFunctions.size)
        val inference = functions.associate { function ->
            function.id to when (val override = overrides[function.id]) {
                null -> inferModule(
                    function,
                    intrinsicModuleByFunction.getValue(function.id),
                    anonymousComponents,
                    affinityIndexes,
                    affinityScratch,
                    complexity,
                )
                else -> safeIdentifier(override) to "user override"
            }
        }

        val grouped = groupFunctions(functions, inference, complexity)
        if (grouped.isEmpty()) grouped["core"] = mutableListOf()

        val sortedGlobals = model.globals.sortedWith(compareBy<RecoveredGlobal> { it.address }.thenBy { it.id })
        sortedGlobals.mapNotNull { overrides[it.id]?.let(::safeIdentifier) }.forEach { module ->
            grouped.putIfAbsent(module, mutableListOf())
        }

        val functionOwner = HashMap<String, String>(functions.size)
        grouped.forEach { (module, members) -> members.forEach { functionOwner[it.id] = module } }

        val firstFunctionReferencingGlobal = HashMap<String, String>()
        functions.forEach { function ->
            function.referencedGlobals.forEach { globalId ->
                complexity.indexedEvidenceEntries++
                if (globalId in globalIds) firstFunctionReferencingGlobal.putIfAbsent(globalId, function.id)
            }
        }
        val globalsByModule = linkedMapOf<String, MutableList<RecoveredGlobal>>()
        sortedGlobals.forEach { global ->
            val module = overrides[global.id]?.let(::safeIdentifier)
                ?: firstFunctionReferencingGlobal[global.id]?.let(functionOwner::getValue)
                ?: grouped.keys.first()
            globalsByModule.getOrPut(module) { mutableListOf() } += global
        }

        val firstModule = grouped.keys.first()
        val functionOwnerByAddress = functions.groupBy(RecoveredFunction::address).mapValues { (_, candidates) ->
            functionOwner.getValue(candidates.minBy(RecoveredFunction::id).id)
        }
        val typesByModule = linkedMapOf<String, MutableList<RecoveredType>>()
        model.types.sortedWith(compareBy<RecoveredType> { it.sourceAddress ?: ULong.MAX_VALUE }.thenBy { it.id })
            .forEach { type ->
                val module = overrides[type.id]?.let(::safeIdentifier)
                    ?: type.sourceAddress?.let(functionOwnerByAddress::get)
                    ?: firstModule
                grouped.putIfAbsent(module, mutableListOf())
                typesByModule.getOrPut(module) { mutableListOf() } += type
                complexity.groupingIndexVisits++
            }

        val dependenciesByModule = linkedMapOf<String, Set<String>>()
        val modules = grouped.map { (id, members) ->
            val referencedModules = sortedSetOf<String>()
            members.forEach { function ->
                function.calls.forEach { calledId ->
                    complexity.moduleGraphVisits++
                    functionOwner[calledId]?.takeIf { it != id }?.let(referencedModules::add)
                }
            }
            dependenciesByModule[id] = referencedModules
            PlannedModule(
                id = id,
                sourcePath = layout.declaration("module-implementation").materialize(mapOf("module" to id)),
                headerPath = layout.declaration("module-interface").materialize(mapOf("module" to id)),
                functionIds = members.map { it.id },
                globalIds = globalsByModule[id].orEmpty().map { it.id },
                typeIds = typesByModule[id].orEmpty().map { it.id },
                boundaryEvidence = buildList {
                    addAll(members.map { inference.getValue(it.id).second }.distinct().sorted())
                    if (referencedModules.isNotEmpty()) add("calls modules: ${referencedModules.joinToString(", ")}")
                },
            )
        }.sortedBy { it.id }

        requireExactOwnership(model, modules)
        val plan = ModulePlan(modules = modules, dependencyCycles = dependencyCycles(dependenciesByModule, complexity))
        val measured = complexity.snapshot(functions.size, model.globals.size, model.types.size)
        require(measured.sparseWorkUnits <= maximumWorkUnits) {
            "module planning required ${measured.sparseWorkUnits} work units; limit=$maximumWorkUnits"
        }
        return IndexedPlannerRun(plan, measured)
    }

    private fun buildAffinityIndexes(
        functions: List<RecoveredFunction>,
        intrinsicModuleByFunction: Map<String, String?>,
        complexity: MutablePlannerComplexity,
    ): AffinityIndexes {
        val namedFunctions = mutableListOf<RecoveredFunction>()
        val namedModules = mutableListOf<String>()
        val namedIndexById = HashMap<String, Int>()
        functions.forEach { function ->
            val module = intrinsicModuleByFunction.getValue(function.id) ?: return@forEach
            namedIndexById[function.id] = namedFunctions.size
            namedFunctions += function
            namedModules += module
        }

        val callersByCallee = HashMap<String, MutableList<Int>>()
        val functionsByGlobal = HashMap<String, MutableList<Int>>()
        val functionsByString = HashMap<String, MutableList<Int>>()
        namedFunctions.forEachIndexed { index, function ->
            function.calls.forEach { calledId ->
                callersByCallee.getOrPut(calledId) { mutableListOf() } += index
                complexity.indexedEvidenceEntries++
            }
            function.referencedGlobals.forEach { globalId ->
                functionsByGlobal.getOrPut(globalId) { mutableListOf() } += index
                complexity.indexedEvidenceEntries++
            }
            function.strings.forEach { string ->
                functionsByString.getOrPut(string) { mutableListOf() } += index
                complexity.indexedEvidenceEntries++
            }
        }
        return AffinityIndexes(
            namedFunctions = namedFunctions,
            namedModules = namedModules,
            namedIndexById = namedIndexById,
            namedCallersByCallee = callersByCallee,
            namedFunctionsByGlobal = functionsByGlobal,
            namedFunctionsByString = functionsByString,
        )
    }

    private class AffinityScratch(namedFunctionCount: Int) {
        val callsSeen = IntArray(namedFunctionCount)
        val globalsSeen = IntArray(namedFunctionCount)
        val stringsSeen = IntArray(namedFunctionCount)
        var stamp = 0

        fun nextStamp(): Int {
            if (stamp == Int.MAX_VALUE) {
                callsSeen.fill(0)
                globalsSeen.fill(0)
                stringsSeen.fill(0)
                stamp = 0
            }
            return ++stamp
        }
    }

    private fun inferModule(
        function: RecoveredFunction,
        intrinsicModule: String?,
        anonymousComponents: Map<String, Pair<String, String>>,
        indexes: AffinityIndexes,
        scratch: AffinityScratch,
        complexity: MutablePlannerComplexity,
    ): Pair<String, String> {
        intrinsicModule?.let { return it to "symbol prefix '${function.name.substringBefore('_')}'" }
        if (indexes.namedModules.isEmpty()) return anonymousComponents.getValue(function.id)

        val stamp = scratch.nextStamp()
        val scores = HashMap<String, Int>()
        val callCandidates = mutableListOf<Int>()
        val stringCandidates = mutableListOf<Int>()
        var hasGlobalCandidate = false

        fun recordCandidate(index: Int, seen: IntArray, candidates: MutableList<Int>?, weight: Int): Boolean {
            if (seen[index] == stamp) return false
            seen[index] = stamp
            candidates?.add(index)
            val module = indexes.namedModules[index]
            scores[module] = scores.getOrDefault(module, 0) + weight
            return true
        }

        function.calls.forEach { calledId ->
            complexity.affinityPostingVisits++
            indexes.namedIndexById[calledId]?.let { recordCandidate(it, scratch.callsSeen, callCandidates, 4) }
        }
        indexes.namedCallersByCallee[function.id].orEmpty().forEach { namedIndex ->
            complexity.affinityPostingVisits++
            recordCandidate(namedIndex, scratch.callsSeen, callCandidates, 4)
        }
        function.referencedGlobals.forEach { globalId ->
            indexes.namedFunctionsByGlobal[globalId].orEmpty().forEach { namedIndex ->
                complexity.affinityPostingVisits++
                if (recordCandidate(namedIndex, scratch.globalsSeen, null, 2)) hasGlobalCandidate = true
            }
        }
        function.strings.forEach { string ->
            indexes.namedFunctionsByString[string].orEmpty().forEach { namedIndex ->
                complexity.affinityPostingVisits++
                recordCandidate(namedIndex, scratch.stringsSeen, stringCandidates, 1)
            }
        }

        if (scores.isEmpty()) return anonymousComponents.getValue(function.id)
        val selected = scores.entries.sortedWith(
            compareByDescending<Map.Entry<String, Int>> { it.value }.thenBy { it.key },
        ).first().key

        val reasons = TreeSet<String>()
        if (callCandidates.any { indexes.namedModules[it] == selected }) {
            reasons += "call-graph affinity to $selected"
        }

        val selectedGlobalsByNamedFunction = linkedMapOf<Int, MutableList<String>>()
        if (hasGlobalCandidate) {
            function.referencedGlobals.sorted().forEach { globalId ->
                indexes.namedFunctionsByGlobal[globalId].orEmpty().forEach { namedIndex ->
                    complexity.affinityPostingVisits++
                    if (indexes.namedModules[namedIndex] == selected) {
                        selectedGlobalsByNamedFunction.getOrPut(namedIndex) { mutableListOf() } += globalId
                    }
                }
            }
        }
        selectedGlobalsByNamedFunction.values.forEach { sharedGlobals ->
            val evidence = sharedGlobals.joinToString(",")
            reasons += "shared globals with $selected: $evidence"
        }
        if (stringCandidates.any { indexes.namedModules[it] == selected }) {
            reasons += "shared strings with $selected"
        }
        return selected to reasons.joinToString("; ")
    }

    private fun anonymousComponents(
        functions: List<RecoveredFunction>,
        intrinsicModuleByFunction: Map<String, String?>,
        complexity: MutablePlannerComplexity,
    ): Map<String, Pair<String, String>> {
        val anonymous = functions.filter { intrinsicModuleByFunction.getValue(it.id) == null }
        val anonymousIndexById = anonymous.mapIndexed { index, function -> function.id to index }.toMap()
        val adjacency = Array(anonymous.size) { mutableListOf<Int>() }
        anonymous.forEachIndexed { index, function ->
            function.calls.forEach { calledId ->
                complexity.anonymousGraphVisits++
                val calledIndex = anonymousIndexById[calledId] ?: return@forEach
                if (calledIndex != index) {
                    adjacency[index] += calledIndex
                    adjacency[calledIndex] += index
                }
            }
        }
        adjacency.forEach { it.sort() }

        val result = HashMap<String, Pair<String, String>>(anonymous.size)
        val visited = BooleanArray(anonymous.size)
        anonymous.indices.forEach { startIndex ->
            if (visited[startIndex]) return@forEach
            visited[startIndex] = true
            val queue = ArrayDeque(listOf(startIndex))
            val members = mutableListOf<Int>()
            while (queue.isNotEmpty()) {
                val index = queue.removeFirst()
                members += index
                adjacency[index].forEach { adjacent ->
                    complexity.anonymousGraphVisits++
                    if (!visited[adjacent]) {
                        visited[adjacent] = true
                        queue.addLast(adjacent)
                    }
                }
            }
            val root = anonymous[startIndex]
            val module = if (members.size == 1) "core" else "component_${root.address.toString(16)}"
            val evidence = if (members.size == 1) {
                "stable address fallback"
            } else {
                "anonymous call-graph component rooted at 0x${root.address.toString(16)}"
            }
            members.forEach { result[anonymous[it].id] = module to evidence }
        }
        return result
    }

    private fun groupFunctions(
        functions: List<RecoveredFunction>,
        inference: Map<String, Pair<String, String>>,
        complexity: MutablePlannerComplexity,
    ): LinkedHashMap<String, MutableList<RecoveredFunction>> {
        val grouped = linkedMapOf<String, MutableList<RecoveredFunction>>()
        val relevantBases = inference.values.mapTo(hashSetOf()) { it.first }
        val matchingGroupCount = HashMap<String, Int>()
        val availableGroups = HashMap<String, ArrayDeque<String>>()

        fun matchingBases(group: String): Set<String> = buildSet {
            if (group in relevantBases) add(group)
            group.indices.filter { group[it] == '_' }.forEach { separator ->
                val prefix = group.substring(0, separator)
                if (prefix in relevantBases) add(prefix)
            }
        }

        fun register(group: String) {
            matchingBases(group).forEach { base ->
                complexity.groupingIndexVisits++
                matchingGroupCount[base] = matchingGroupCount.getOrDefault(base, 0) + 1
                availableGroups.getOrPut(base) { ArrayDeque() }.addLast(group)
            }
        }

        functions.forEach { function ->
            val base = inference.getValue(function.id).first
            val available = availableGroups.getOrPut(base) { ArrayDeque() }
            while (available.isNotEmpty() && grouped.getValue(available.last()).size >= maximumFunctionsPerModule) {
                complexity.groupingIndexVisits++
                available.removeLast()
            }
            val target = available.lastOrNull()
                ?: matchingGroupCount[base]?.let { count -> "${base}_${count + 1}" }
                ?: base
            val members = grouped[target] ?: mutableListOf<RecoveredFunction>().also {
                grouped[target] = it
                register(target)
            }
            members += function
        }
        return grouped
    }

    /** Returns each cyclic strongly-connected module group once, instead of enumerating every path. */
    private fun dependencyCycles(
        graph: Map<String, Set<String>>,
        complexity: MutablePlannerComplexity,
    ): List<List<String>> {
        val nodes = graph.keys.sorted()
        val adjacency = nodes.associateWith { node -> graph[node].orEmpty().filter { it in graph }.sorted() }
        val reverse = nodes.associateWith { mutableListOf<String>() }
        adjacency.forEach { (from, targets) ->
            targets.forEach { to ->
                complexity.moduleGraphVisits++
                reverse.getValue(to) += from
            }
        }
        reverse.values.forEach { it.sort() }

        data class Frame(val node: String, var nextEdge: Int = 0)

        val visited = hashSetOf<String>()
        val finished = mutableListOf<String>()
        nodes.forEach { start ->
            if (!visited.add(start)) return@forEach
            val stack = ArrayDeque<Frame>()
            stack.addLast(Frame(start))
            while (stack.isNotEmpty()) {
                val frame = stack.last()
                val targets = adjacency.getValue(frame.node)
                if (frame.nextEdge < targets.size) {
                    val target = targets[frame.nextEdge++]
                    complexity.moduleGraphVisits++
                    if (visited.add(target)) stack.addLast(Frame(target))
                } else {
                    finished += frame.node
                    stack.removeLast()
                }
            }
        }

        val assigned = hashSetOf<String>()
        val cyclicGroups = mutableListOf<List<String>>()
        finished.asReversed().forEach { start ->
            if (!assigned.add(start)) return@forEach
            val component = mutableListOf<String>()
            val stack = ArrayDeque(listOf(start))
            while (stack.isNotEmpty()) {
                val node = stack.removeLast()
                component += node
                reverse.getValue(node).asReversed().forEach { previous ->
                    complexity.moduleGraphVisits++
                    if (assigned.add(previous)) stack.addLast(previous)
                }
            }
            if (component.size > 1) cyclicGroups += component.sorted()
        }
        return cyclicGroups.sortedBy { it.joinToString("\u0000") }
    }

    private fun requireExactOwnership(model: RecoveredProgramModel, modules: List<PlannedModule>) {
        val plannedFunctions = modules.flatMap { it.functionIds }
        val plannedGlobals = modules.flatMap { it.globalIds }
        val plannedTypes = modules.flatMap { it.typeIds }
        require(plannedFunctions.size == model.functions.size && plannedFunctions.toSet() == model.functions.mapTo(hashSetOf()) { it.id }) {
            "planner must assign every function exactly once"
        }
        require(plannedGlobals.size == model.globals.size && plannedGlobals.toSet() == model.globals.mapTo(hashSetOf()) { it.id }) {
            "planner must assign every global exactly once"
        }
        require(plannedTypes.size == model.types.size && plannedTypes.toSet() == model.types.mapTo(hashSetOf()) { it.id }) {
            "planner must assign every type exactly once"
        }
    }

    private fun namedModule(function: RecoveredFunction): String? {
        val meaningfulName = function.name.takeUnless { it.startsWith("FUN_") || it.startsWith("sub_") || it.startsWith("fn_") }
        val prefix = meaningfulName?.substringBefore('_')?.takeIf { it.length >= 3 }
        return prefix?.let(::safeIdentifier)
    }
}
