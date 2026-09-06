package decompengine.project

/** Deterministic dependency-first DFS order; cycles retain the historical DFS tie breaking. */
internal fun moduleDependencyOrder(dependencies: Map<String, List<String>>): List<String> {
    require(dependencies.values.all { edges -> edges.all { it in dependencies } }) {
        "module dependency references an unknown module"
    }
    data class Frame(val id: String, val children: Iterator<String>)
    val ordered = ArrayList<String>(dependencies.size)
    val entered = HashSet<String>()
    val stack = ArrayDeque<Frame>()
    fun enter(id: String) {
        if (entered.add(id)) stack.addLast(Frame(id, dependencies.getValue(id).sorted().iterator()))
    }
    for (root in dependencies.keys.sorted()) {
        enter(root)
        while (stack.isNotEmpty()) {
            val frame = stack.last()
            if (frame.children.hasNext()) enter(frame.children.next())
            else {
                ordered += frame.id
                stack.removeLast()
            }
        }
    }
    return ordered
}
