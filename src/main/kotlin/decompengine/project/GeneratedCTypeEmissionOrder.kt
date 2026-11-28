package decompengine.project

import java.util.PriorityQueue

/** Sort indivisible original records by direct declaration and completeness prerequisites. */
@JvmOverloads
internal fun generatedCTypeEmissionOrder(types: List<RecoveredType>, checkpoint: () -> Unit = {}): List<RecoveredType> {
    fun cancellation() {
        checkpoint()
        if (Thread.currentThread().isInterrupted) throw InterruptedException("generated-C type ordering cancelled")
    }
    cancellation()
    require(types.size <= 4096) { "generated-C type inventory exceeds 4096 definitions" }
    var text = 0L
    for (type in types) {
        cancellation()
        require(type.id.length <= 4096 && type.declaration.length <= 65_536) { "generated-C type field exceeds its bound" }
        text += type.id.length + type.declaration.length
        require(text <= 4L * 1024 * 1024) { "generated-C type source exceeds its bound" }
    }
    // This legacy admission guard is independent of the actual shared inventory meter.
    require(text * types.size <= 64L * 1024 * 1024) { "generated-C dependency inventory work exceeds its bound" }
    val byId = types.associateBy { cancellation(); it.id }
    require(byId.size == types.size) { "duplicate generated-C type identity" }
    var work = 0L
    fun charge(units: Long) {
        cancellation()
        require(units >= 0 && units <= 64L * 1024 * 1024 - work) { "generated-C dependency inventory work exceeds its bound" }
        work += units
    }
    val sorted = types.sortedWith { left, right -> charge(1); left.id.compareTo(right.id) }
    val inventory = generatedCTypeOrderInventory(sorted, ::cancellation, ::charge)
    val dependencies = sorted.associateTo(linkedMapOf()) { charge(1); it.id to linkedSetOf<String>() }
    val users = mutableMapOf<String, MutableList<String>>()
    var edges = 0
    fun edge(user: String, provider: String) {
        charge(1)
        if (user != provider && provider !in dependencies.getValue(user)) {
            require(edges < 65_536) { "generated-C dependency edges exceed their bound" }
            dependencies.getValue(user).add(provider)
            edges++
        }
    }
    val exports = inventory.exports.groupBy { charge(1); it.symbol }
    fun precedes(export: COrderExport, at: COrderSite): Boolean = export.site.ownerId < at.ownerId ||
        export.site.ownerId == at.ownerId && export.availableOffset <= at.originalOffset
    val canonical = Comparator<COrderExport> { left, right ->
        charge(1)
        val owner = left.site.ownerId.compareTo(right.site.ownerId)
        if (owner == 0) left.availableOffset.compareTo(right.availableOffset) else owner
    }
    val introduction = Comparator<COrderExport> { left, right ->
        charge(1)
        val owner = left.site.ownerId.compareTo(right.site.ownerId)
        if (owner == 0) left.site.originalOffset.compareTo(right.site.originalOffset) else owner
    }
    for (use in inventory.uses) {
        charge(1)
        val candidates = exports[use.symbol].orEmpty().filter { charge(1); it.site.scopeId == 0 }
        val chosen = when (use.need) {
            COrderNeed.ALIAS_DECL, COrderNeed.ENUM_VALUE -> candidates.minWithOrNull(canonical)
            COrderNeed.COMPLETE_BODY -> candidates.filter { charge(1); it.definition }
                .minWithOrNull(canonical)
            COrderNeed.TAG_VISIBLE -> candidates.filter { charge(1); precedes(it.copy(availableOffset = it.site.originalOffset), use.site) }
                .minWithOrNull(introduction)
        }
        require(chosen != null) { "unresolved generated-C ${use.need} prerequisite in ${use.site.ownerId}: ${use.symbol}" }
        val available = if (use.need == COrderNeed.TAG_VISIBLE) chosen.site.originalOffset else chosen.availableOffset
        // Retained same-record alias syntax remains compiler-owned. In particular, existing
        // function/global shape validation supplies the affected entity for cyclic typedefs.
        // Keep the use in the inventory; record sorting cannot repair its internal order.
        require(use.need == COrderNeed.ALIAS_DECL || chosen.site.ownerId != use.site.ownerId || available <= use.site.originalOffset) {
            "unresolved generated-C ${use.need} prerequisite within ${use.site.ownerId}: ${use.symbol}"
        }
        edge(use.site.ownerId, chosen.site.ownerId)
    }
    // Standalone forwards are harmless and preserve the established forward-before-body policy.
    val standalone = Regex("\\s*(?:struct|union)\\s+[A-Za-z_][A-Za-z0-9_]*\\s*;\\s*")
    val standaloneIds = hashSetOf<String>()
    for (type in sorted) {
        charge(type.declaration.length.toLong())
        for (offset in type.declaration.indices step 256) cancellation()
        if (standalone.matches(type.declaration)) standaloneIds += type.id
    }
    for ((symbol, candidates) in exports) {
        charge(1)
        if (symbol !is COrderSymbol.Tag) continue
        val forwards = candidates.filter {
            charge(1); !it.definition && it.site.scopeId == 0 && it.site.ownerId in standaloneIds
        }
        for (body in candidates.filter { charge(1); it.definition && it.site.scopeId == 0 }) for (forward in forwards) {
            edge(body.site.ownerId, forward.site.ownerId)
        }
    }
    for ((id, required) in dependencies) {
        charge(1)
        for (dependency in required) {
            charge(1)
            users.getOrPut(dependency) { mutableListOf() }.add(id)
        }
    }
    val ready = PriorityQueue<String>()
    for ((id, required) in dependencies) { charge(1); if (required.isEmpty()) ready.add(id) }
    val ordered = ArrayList<RecoveredType>(types.size)
    while (ready.isNotEmpty()) {
        charge(1)
        val id = ready.remove()
        ordered += byId.getValue(id)
        for (user in users[id].orEmpty()) {
            charge(1)
            if (dependencies.getValue(user).remove(id) && dependencies.getValue(user).isEmpty()) ready.add(user)
        }
    }
    require(ordered.size == types.size) {
        "unresolved generated-C type dependency cycle: " + dependencies.filterValues { charge(1); it.isNotEmpty() }.keys.joinToString(",")
    }
    return ordered.toList()
}
