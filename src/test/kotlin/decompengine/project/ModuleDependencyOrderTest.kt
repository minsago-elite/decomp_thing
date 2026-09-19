package decompengine.project

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class ModuleDependencyOrderTest {
    @Test
    fun `deep chains retain dependency-first ordering without call-stack depth`() {
        val ids = (0 until 20_000).map { "module_${it.toString().padStart(5, '0')}" }
        val graph = ids.mapIndexed { index, id -> id to ids.getOrNull(index + 1)?.let(::listOf).orEmpty() }.toMap()
        assertEquals(ids.reversed(), moduleDependencyOrder(graph))
    }

    @Test
    fun `cycles diamonds duplicate edges and disconnected nodes have stable ordering`() {
        val graph = linkedMapOf(
            "root" to listOf("right", "left", "left"),
            "right" to listOf("leaf"),
            "left" to listOf("leaf"),
            "leaf" to emptyList(),
            "cycle_a" to listOf("cycle_b"),
            "cycle_b" to listOf("cycle_a", "cycle_b"),
            "unrelated" to emptyList(),
        )
        val expected = listOf("cycle_b", "cycle_a", "leaf", "left", "right", "root", "unrelated")
        assertEquals(expected, moduleDependencyOrder(graph))
        assertEquals(expected, moduleDependencyOrder(graph.entries.reversed().associate { it.key to it.value.reversed() }))
        assertTrue(moduleDependencyOrder(emptyMap()).isEmpty())
    }

    @Test
    fun `unknown dependencies are rejected before scheduling`() {
        assertFailsWith<IllegalArgumentException> { moduleDependencyOrder(mapOf("module" to listOf("absent"))) }
    }
}
