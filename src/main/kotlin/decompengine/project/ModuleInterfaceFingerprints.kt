package decompengine.project

import kotlinx.serialization.json.JsonPrimitive

/** Hash each strongly connected component once, then fold dependency hashes through the component DAG. */
internal fun moduleInterfaceFingerprints(
    dependencies: Map<String, List<String>>,
    headerHashes: Map<String, String>,
): Map<String, String> {
    require(dependencies.keys == headerHashes.keys) { "module interfaces and dependency nodes differ" }
    val graph = dependencies.mapValues { it.value.distinct().sorted() }
    val finishingOrder = moduleDependencyOrder(graph)
    val reverse = graph.keys.associateWith { mutableListOf<String>() }
    graph.forEach { (id, children) -> children.forEach { reverse.getValue(it).add(id) } }
    val entered = mutableSetOf<String>()
    val owner = mutableMapOf<String, String>()
    val components = linkedMapOf<String, List<String>>()
    for (root in finishingOrder.asReversed()) {
        if (!entered.add(root)) continue
        val pending = ArrayDeque<String>()
        pending.addLast(root)
        val members = mutableListOf<String>()
        while (pending.isNotEmpty()) {
            val next = pending.removeLast()
            members += next
            reverse.getValue(next).forEach { if (entered.add(it)) pending.addLast(it) }
        }
        members.sort()
        val component = members.first()
        components[component] = members
        members.forEach { owner[it] = component }
    }
    val componentDependencies = components.mapValues { (component, members) ->
        members.flatMap { graph.getValue(it) }.map { owner.getValue(it) }
            .filter { it != component }.distinct().sorted()
    }
    val hashes = mutableMapOf<String, String>()
    for (component in moduleDependencyOrder(componentDependencies)) {
        val commitment = buildString {
            append("module-interface-component-v1\n")
            for (member in components.getValue(component)) {
                append("member:").append(JsonPrimitive(member)).append(':')
                    .append(JsonPrimitive(headerHashes.getValue(member))).append('\n')
            }
            for (dependency in componentDependencies.getValue(component)) {
                append("dependency:").append(JsonPrimitive(dependency)).append(':')
                    .append(hashes.getValue(dependency)).append('\n')
            }
        }
        hashes[component] = sha256(commitment.toByteArray())
    }
    return graph.keys.associateWith { hashes.getValue(owner.getValue(it)) }
}
