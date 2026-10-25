package decompengine.project

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class GeneratedCTypeSelectionTest {
    @Test
    fun `typedef storage specifier can follow type qualifiers`() {
        val alias = RecoveredType("alias", "const typedef int Value;")
        assertEquals(listOf(alias), selectRequiredGeneratedCTypes(listOf(alias), listOf("Value get(void)")))
    }

    @Test
    fun `selection follows typedef and aggregate dependencies while omitting unrelated records`() {
        val types = listOf(
            RecoveredType("unused", "typedef double Unrelated;"),
            RecoveredType("value", "typedef unsigned long Value;"),
            RecoveredType("node", "struct Node { Value value; struct Node *next; };"),
            RecoveredType("alias", "typedef struct Node NodeAlias;"),
        )
        assertEquals(listOf("alias", "node", "value"),
            selectRequiredGeneratedCTypes(types, listOf("NodeAlias *walk(NodeAlias *head)")).map { it.id })
        assertEquals(selectRequiredGeneratedCTypes(types, listOf("NodeAlias *walk(NodeAlias *head)")),
            selectRequiredGeneratedCTypes(types.reversed(), listOf("NodeAlias *walk(NodeAlias *head)")))
    }

    @Test
    fun `tag names do not select unrelated ordinary aliases with the same spelling`() {
        val types = listOf(
            RecoveredType("ordinary", "typedef int Entry;"),
            RecoveredType("tag", "struct Entry { int value; };"),
        )
        assertEquals(listOf("tag"), selectRequiredGeneratedCTypes(types,
            listOf("int use(struct Entry *entry)")).map { it.id })
        assertEquals(listOf("ordinary"), selectRequiredGeneratedCTypes(types,
            listOf("Entry use(void)")).map { it.id })
    }

    @Test
    fun `enum values select their declaration and transitive initializer dependencies`() {
        val types = listOf(
            RecoveredType("base", "enum { BASE = 3 };"),
            RecoveredType("modes", "enum Mode { MODE_FIRST = BASE, MODE_SECOND = (BASE + 1) };"),
            RecoveredType("unrelated", "enum Other { UNUSED = 9 };"),
        )
        assertEquals(listOf("base", "modes"), selectRequiredGeneratedCTypes(types,
            listOf("int run(void) { return MODE_SECOND; }")).map { it.id })
    }

    @Test
    fun `comments literals and numeric suffixes do not create type dependencies`() {
        val types = listOf(RecoveredType("unused", "typedef int Unrelated;"),
            RecoveredType("suffix", "typedef int U;"))
        val body = "int run(void) { /* Unrelated */ const char *text = \"Unrelated\"; // Unrelated\n return 3U + 'U'; }"
        assertEquals(emptyList(), selectRequiredGeneratedCTypes(types, listOf(body)))
    }

    @Test
    fun `a required complete tag supersedes its separate forward declaration`() {
        val types = listOf(
            RecoveredType("forward", "struct Item;"),
            RecoveredType("definition", "struct Item { int value; };"),
        )
        assertEquals(listOf("definition"), selectRequiredGeneratedCTypes(types,
            listOf("struct Item *get(void)")).map { it.id })
        assertEquals(listOf("forward"), selectRequiredGeneratedCTypes(types.take(1),
            listOf("struct Item *get(void)")).map { it.id })
    }

    @Test
    fun `needed conflicts fail without rejecting an unrelated ambiguity`() {
        val types = listOf(
            RecoveredType("first", "typedef int Value;"),
            RecoveredType("second", "typedef long Value;"),
            RecoveredType("safe", "typedef unsigned Safe;"),
        )
        assertEquals(listOf("safe"), selectRequiredGeneratedCTypes(types, listOf("Safe get(void)")).map { it.id })
        val failure = assertFailsWith<IllegalArgumentException> {
            selectRequiredGeneratedCTypes(types, listOf("Value get(void)"))
        }
        assertTrue(failure.message.orEmpty().contains("ambiguous recovered type dependency name:Value"))
        assertFailsWith<IllegalArgumentException> {
            selectRequiredGeneratedCTypes(listOf(RecoveredType("first", "typedef struct { int value; } Value;"),
                RecoveredType("second", "typedef struct { long value; } Value;")), listOf("Value get(void)"))
        }
    }

    @Test
    fun `multiple declarators preserve the selected recovered record as one evidence unit`() {
        val type = RecoveredType("aliases", "typedef int Value, *ValuePointer, Values[2];")
        assertEquals(listOf(type), selectRequiredGeneratedCTypes(listOf(type), listOf("ValuePointer get(void)")))
    }
}
