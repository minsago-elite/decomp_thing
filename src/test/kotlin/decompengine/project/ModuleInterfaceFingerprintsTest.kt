package decompengine.project

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals

class ModuleInterfaceFingerprintsTest {
    @Test
    fun `header changes invalidate exactly their consumers for every three-node graph`() {
        val ids = listOf("a", "b", "c")
        val headers = ids.associateWith { sha256(it.toByteArray()) }
        for (mask in 0 until (1 shl 9)) {
            val graph = ids.mapIndexed { from, id ->
                id to ids.filterIndexed { to, _ -> mask and (1 shl (from * 3 + to)) != 0 }
            }.toMap()
            val before = moduleInterfaceFingerprints(graph, headers)
            for (changed in ids) {
                val after = moduleInterfaceFingerprints(graph, headers + (changed to sha256("changed".toByteArray())))
                for (root in ids) {
                    // Independent reachability specification, including the module's own interface.
                    val reachable = mutableSetOf(root)
                    do {
                        val previousSize = reachable.size
                        reachable += reachable.toList().flatMap { graph.getValue(it) }
                    } while (reachable.size != previousSize)
                    assertEquals(changed in reachable, before.getValue(root) != after.getValue(root), "graph=$mask root=$root changed=$changed")
                }
            }
        }
    }

    @Test
    fun `deep chains and a large cycle compute shared fingerprints without recursion`() {
        val ids = (0 until 20_000).map { "module_${it.toString().padStart(5, '0')}" }
        val headers = ids.associateWith { sha256(it.toByteArray()) }
        val chain = ids.mapIndexed { index, id -> id to ids.getOrNull(index + 1)?.let(::listOf).orEmpty() }.toMap()
        val fingerprints = moduleInterfaceFingerprints(chain, headers)
        assertEquals(ids.size, fingerprints.size)
        assertEquals(ids.size, fingerprints.values.toSet().size)
        val cycle = chain + (ids.last() to listOf(ids.first()))
        val cycleFingerprints = moduleInterfaceFingerprints(cycle, headers)
        assertEquals(1, cycleFingerprints.values.toSet().size)
        assertNotEquals(fingerprints.getValue(ids.first()), cycleFingerprints.getValue(ids.first()))
    }

    @Test
    fun `ordering and duplicate edges do not alter fingerprints and incomplete graphs fail`() {
        val graph = linkedMapOf("a" to listOf("b", "c"), "b" to listOf("c"), "c" to emptyList())
        val headers = graph.keys.associateWith { sha256(it.toByteArray()) }
        val reordered = graph.entries.reversed().associate { it.key to (it.value.reversed() + it.value) }
        assertEquals(moduleInterfaceFingerprints(graph, headers), moduleInterfaceFingerprints(reordered, headers))
        assertEquals(emptyMap(), moduleInterfaceFingerprints(emptyMap(), emptyMap()))
        assertFailsWith<IllegalArgumentException> { moduleInterfaceFingerprints(graph, headers - "a") }
        assertFailsWith<IllegalArgumentException> { moduleInterfaceFingerprints(graph + ("a" to listOf("missing")), headers) }
    }
}
