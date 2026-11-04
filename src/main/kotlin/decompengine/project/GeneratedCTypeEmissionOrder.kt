package decompengine.project

import java.util.PriorityQueue

/** Orders retained declarations without modifying them or manufacturing definitions.
 * The existing selector supplies a conservative, transitive dependency inventory. Its ambiguity
 * checks remain authoritative; a conservative cycle is refused, never broken by hash order.
 */
internal fun generatedCTypeEmissionOrder(types: List<RecoveredType>): List<RecoveredType> {
    fun cancellation() {
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
    // The selector builds an inventory per query. Bound that aggregate work *before* invoking it.
    require(text * types.size <= 64L * 1024 * 1024) { "generated-C dependency inventory work exceeds its bound" }
    val byId = types.associateBy { it.id }
    require(byId.size == types.size) { "duplicate generated-C type identity" }
    val sorted = types.sortedWith { left, right -> cancellation(); left.id.compareTo(right.id) }
    // Lexical spans only: the frozen selector remains the authority for declarations and
    // file/prototype scope. Keep comments and quoted literals out of reference evidence.
    val tokenPattern = Regex("""(?s)/\*.*?\*/|//[^\r\n]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[A-Za-z_][A-Za-z0-9_]*|[^\s]""")
    val identifier = Regex("[A-Za-z_][A-Za-z0-9_]*")
    val standaloneForward = Regex("\\s*(?:struct|union)\\s+[A-Za-z_][A-Za-z0-9_]*\\s*;\\s*")
    var inventoryWork = text * types.size
    fun inventory(context: List<RecoveredType>, evidence: String): List<RecoveredType> {
        cancellation()
        inventoryWork += context.sumOf { it.declaration.length.toLong() } + evidence.length
        require(inventoryWork <= 64L * 1024 * 1024) { "generated-C dependency inventory work exceeds its bound" }
        return selectRequiredGeneratedCTypes(context, listOf(evidence))
    }
    val dependencies = linkedMapOf<String, MutableSet<String>>()
    val users = mutableMapOf<String, MutableList<String>>()
    val introductions = mutableMapOf<String, MutableSet<String>>()
    val bodies = mutableMapOf<String, MutableSet<String>>()
    var edges = 0L
    for (type in sorted) {
        cancellation()
        val selected = selectRequiredGeneratedCTypes(sorted, listOf(type.declaration))
        // Query prerequisites separately from the transitive retention inventory. A file-scope
        // pointer or bodyless typedef introduces a tag without requiring its complete body.
        // Suppress only those reference tokens in *query evidence*, never in emitted source.
        // Excluding this record prevents its own exports from reintroducing the suppressed
        // references through the selector's transitive walk. Alias and by-value uses remain.
        val tokens = tokenPattern.findAll(type.declaration).filterNot {
            it.value.startsWith("/*") || it.value.startsWith("//")
        }.map { cancellation(); CToken(it.value, it.range.first, it.range.last + 1) }.toList()
        val evidence = StringBuilder(type.declaration)
        var refined = false
        for (index in tokens.indices) {
            cancellation()
            val kind = tokens[index]
            if (kind.text !in setOf("struct", "union")) continue
            val tag = tokens.getOrNull(index + 1) ?: continue
            if (!tag.text.matches(identifier)) continue
            var next = index + 2
            while (tokens.getOrNull(next)?.text in setOf("const", "volatile", "restrict", "_Atomic")) next++
            val statementStart = (index - 1 downTo 0).firstOrNull { tokens[it].text in setOf(";", "{", "}") }?.plus(1) ?: 0
            val bodylessAlias = tokens[statementStart].text == "typedef" &&
                tokens.getOrNull(next)?.text?.matches(identifier) == true &&
                tokens.getOrNull(next + 1)?.text == ";"
            val incompleteUse = tokens.getOrNull(next)?.text in setOf("*", ";") || bodylessAlias
            val definesBody = tokens.getOrNull(next)?.text == "{"
            if (!incompleteUse && !definesBody) continue
            val reference = "${kind.text} ${tag.text}"
            // The frozen selector's scope inventory proves authentic introductions, including
            // nested aggregate members, and excludes function-pointer parameter scopes.
            if (inventory(listOf(type), reference).isEmpty()) continue
            if (definesBody) bodies.getOrPut(reference) { mutableSetOf() }.add(type.id)
            else introductions.getOrPut(reference) { mutableSetOf() }.add(type.id)
            // A body defines its own tag; it does not require records that merely mention
            // that tag by value. Authentic incomplete introductions are ordered separately.
            for (offset in kind.start until tag.end) evidence.setCharAt(offset, ' ')
            refined = true
        }
        val retained = selected.mapTo(hashSetOf()) { it.id }
        val required = (if (refined) inventory(sorted.filter { it.id != type.id }, evidence.toString()) else selected)
            .asSequence().map { it.id }.filter { it != type.id && it in retained }.toMutableSet()
        if ('(' in type.declaration) {
            // Hoisting a later tag body in front of a prototype-local tag would silently change C
            // type identity. The selector can prove a prior file-scope introduction; absent that
            // proof, refuse the ambiguous dependency instead of changing the declaration's meaning.
            for (reference in tokens.zipWithNext().filter { (kind, tag) ->
                kind.text in setOf("struct", "union", "enum") && tag.text.matches(identifier)
            }.map { (kind, tag) -> "${kind.text} ${tag.text}" }.distinct()) {
                cancellation()
                val earlier = sorted.takeWhile { it.id < type.id }
                if (inventory(earlier, reference).isNotEmpty()) continue
                for (dependency in selected.filter { it.id > type.id }) {
                    require(inventory(listOf(dependency), reference).isEmpty()) {
                        "ambiguous generated-C prototype tag dependency in ${type.id}: $reference"
                    }
                }
            }
        }
        edges += required.size
        require(edges <= 65_536) { "generated-C dependency edges exceed their bound" }
        dependencies[type.id] = required
    }
    for ((reference, definitions) in bodies) for (body in definitions) {
        cancellation()
        for (intro in introductions[reference].orEmpty()) {
            cancellation()
            // An aggregate may both introduce Foo through a pointer and need Foo by value
            // elsewhere. That record must follow the body, not form an artificial cycle.
            if ((intro < body || standaloneForward.matches(byId.getValue(intro).declaration)) &&
                intro != body && body !in dependencies.getValue(intro) && dependencies.getValue(body).add(intro)) {
                require(++edges <= 65_536) { "generated-C dependency edges exceed their bound" }
            }
        }
    }
    for ((id, required) in dependencies) {
        cancellation()
        for (dependency in required) {
            cancellation()
            require(dependency in byId) { "unresolved generated-C dependency $dependency" }
            users.getOrPut(dependency) { mutableListOf() }.add(id)
        }
    }
    require(dependencies.values.sumOf { it.size.toLong() } <= 65_536) { "generated-C dependency edges exceed their bound" }
    val ready = PriorityQueue<String>()
    dependencies.filterValues { it.isEmpty() }.keys.forEach(ready::add)
    val ordered = ArrayList<RecoveredType>(types.size)
    while (ready.isNotEmpty()) {
        cancellation()
        val id = ready.remove()
        ordered += byId.getValue(id)
        for (user in users[id].orEmpty()) {
            cancellation()
            if (dependencies.getValue(user).remove(id) && dependencies.getValue(user).isEmpty()) ready.add(user)
        }
    }
    require(ordered.size == types.size) {
        "unresolved generated-C type dependency cycle: " + dependencies.filterValues { it.isNotEmpty() }.keys.joinToString(",")
    }
    return ordered.toList()
}
