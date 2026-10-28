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
    fun `earlier tag introductions survive selection without widening namespaces or prototype scope`() {
        for (tag in listOf("Foo", "decomp_context_tag")) {
            for (introduction in listOf(
                "struct $tag;",
                "typedef struct $tag FooAlias;",
                "const typedef struct $tag *FooPointer, **FooPointerPointer;",
            )) {
                val dependency = RecoveredType("a08_dependency", "typedef long ExtraDependency;")
                val first = RecoveredType("a10_introduction", "$introduction\n typedef ExtraDependency ExtraAlias;")
                val callback = RecoveredType("a20_callback", "typedef int (*Fn)(struct $tag *);")
                val definition = RecoveredType("a30_definition", "struct $tag { int value; };")
                val types = listOf(
                    // These selector-only distractors are not an asserted compilable full header.
                    RecoveredType("a00_prototype", "typedef int (*Other)(struct $tag *);"),
                    RecoveredType("a02_wrong_kind", "union $tag;"),
                    RecoveredType("a05_anonymous", "typedef struct { int value; } UnrelatedAnonymous;"),
                    dependency,
                    first,
                    RecoveredType("a15_duplicate", "struct $tag;"),
                    callback,
                    definition,
                    RecoveredType("a40_late", "struct $tag;"),
                    RecoveredType("a50_ordinary", "typedef int $tag;"),
                    RecoveredType("a60_unrelated", "struct Unrelated { int value; };"),
                )
                val expected = listOf(dependency, first, callback, definition)
                assertEquals(expected, selectRequiredGeneratedCTypes(types, listOf("Fn choose(void)")), introduction)
                assertEquals(expected, selectRequiredGeneratedCTypes(types.reversed(), listOf("Fn choose(void)")), introduction)
                val conflict = RecoveredType("a35_conflict", "struct $tag { long value; };")
                val failure = assertFailsWith<IllegalArgumentException>(introduction) {
                    selectRequiredGeneratedCTypes(types + conflict, listOf("Fn choose(void)"))
                }
                assertTrue(failure.message.orEmpty().contains("ambiguous recovered type dependency tag:$tag"), failure.message)
            }
        }
    }

    @Test
    fun `aggregate member introductions retain the complete earlier record and its dependencies`() {
        for (tag in listOf("Foo", "decomp_context_tag")) {
            for (introduction in listOf(
                "struct Holder { struct $tag *p; };",
                "union Holder { const struct $tag *p, **q; };",
                "struct Holder { struct Nested { struct $tag *p; } nested; };",
                "typedef struct { struct $tag *p; } Holder;",
                "struct Holder { _Atomic(struct $tag *) p; };",
                "struct Holder { _Alignas(8) struct $tag *p; };",
                "struct Holder { _Alignas(struct $tag *) int value; };",
                "struct Holder { struct $tag *values[2]; };",
                "struct Holder { struct $tag *p; } holder = {0};",
            )) {
                val dependency = RecoveredType("a05_dependency", "typedef long ExtraDependency;")
                val holder = RecoveredType("a10_holder", "$introduction\ntypedef ExtraDependency ExtraAlias;")
                val callback = RecoveredType("a20_callback", "typedef int (*Fn)(struct $tag *);")
                val complete = RecoveredType("a30_definition", "struct $tag { int value; };")
                val types = listOf(
                    // These are selector-only distractors, not a claimed valid complete header.
                    RecoveredType("a00_prototype", "typedef struct Prefix { int x; } (*Other)(struct $tag *);"),
                    RecoveredType("a01_member_prototype", "struct OtherHolder { int (*cb)(struct $tag *); };"),
                    RecoveredType("a02_atomic_prototype", "struct AtomicHolder { _Atomic(int (*)(struct $tag *)) cb; };"),
                    RecoveredType("a03_wrong_kind", "union $tag;"),
                    RecoveredType("a04_aligned_prototype", "struct AlignedHolder { _Alignas(8) int (*cb)(struct $tag { long other; } *); };"),
                    dependency, holder,
                    RecoveredType("a15_duplicate", "struct $tag;"), callback, complete,
                    RecoveredType("a40_late", "struct $tag;"),
                )
                val expected = listOf(dependency, holder, callback, complete)
                assertEquals(expected, selectRequiredGeneratedCTypes(types, listOf("Fn choose(void)")), introduction)
                assertEquals(expected, selectRequiredGeneratedCTypes(types.reversed(), listOf("Fn choose(void)")), introduction)
            }
        }
    }

    @Test
    fun `prototype local aggregate definitions and enumerators do not become file scope exports`() {
        val prototype = RecoveredType("a00_prototype", """
            typedef struct Prefix { int first; } (*Other)(struct Hidden {
                enum HiddenMode { PROTOTYPE_VALUE = 1 } mode;
                struct Foo *pointer;
            } *);
        """.trimIndent())
        val memberPrototype = RecoveredType("a01_member_prototype", """
            struct OtherHolder {
                struct Prefix2 { int first; } value, (*callback)(struct Foo *);
            };
        """.trimIndent())
        val holder = RecoveredType("a10_holder", "struct Holder { enum VisibleMode { FILE_VALUE = 2 } mode; struct Foo *p; };")
        val callback = RecoveredType("a20_callback", "typedef int (*Fn)(struct Foo *);")
        val complete = RecoveredType("a30_definition", "struct Foo { int value; };")
        val types = listOf(prototype, memberPrototype, holder, callback, complete)
        assertEquals(listOf(holder, callback, complete), selectRequiredGeneratedCTypes(types, listOf("Fn choose(void)")))
        assertEquals(emptyList(), selectRequiredGeneratedCTypes(types, listOf("int get(void) { return PROTOTYPE_VALUE; }")))
        assertEquals(emptyList(), selectRequiredGeneratedCTypes(types, listOf("struct Hidden *get(void)")))
        assertEquals(listOf(holder, complete), selectRequiredGeneratedCTypes(types, listOf("int get(void) { return FILE_VALUE; }")))
    }

    @Test
    fun `additional scope analysis does not impose declarator parsing on unrelated recovered records`() {
        val extended = RecoveredType("a00_extended", "struct Packed { unsigned bits : 3; int value; } __attribute__((packed));")
        val safe = RecoveredType("a10_safe", "struct Safe { int value; };")
        assertEquals(listOf(safe), selectRequiredGeneratedCTypes(listOf(extended, safe), listOf("struct Safe *get(void)")))
        assertEquals(listOf(extended), selectRequiredGeneratedCTypes(listOf(extended, safe), listOf("struct Packed *get(void)")))
    }

    @Test
    fun `previously admitted bodyless enum typedef introductions keep their selection behavior`() {
        val introduction = RecoveredType("a10_enum", "typedef enum Mode ModeAlias;")
        val callback = RecoveredType("a20_callback", "typedef enum Mode (*Fn)(void);")
        val complete = RecoveredType("a30_definition", "enum Mode { MODE_FIRST = 1 };")
        assertEquals(listOf(introduction, callback, complete), selectRequiredGeneratedCTypes(
            listOf(introduction, callback, complete), listOf("Fn choose(void)")))
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
    fun `equivalent repeated aliases ignore sibling declarators and retain whole records`() {
        for ((multiple, single) in listOf(
            "typedef int Value, Other;" to "typedef int Value;",
            "typedef int Other, Value;" to "typedef int Value;",
            "const typedef unsigned long Other, *Value;" to "const typedef unsigned long *Value;",
            "typedef int (*Other)(long), (*Value)(int);" to "typedef int (*Value)(int);",
            "typedef int Other[3], Value[2];" to "typedef int Value[2];",
            "typedef int Value /* comma , in comment */, Other;" to "typedef int Value;",
        )) {
            for ((earlier, later) in listOf(multiple to single, single to multiple)) {
                val first = RecoveredType("a00_first", earlier)
                val second = RecoveredType("a10_repeat", later)
                val types = listOf(first, second)
                assertEquals(listOf(first), selectRequiredGeneratedCTypes(types, listOf("Value choose(void)")), earlier)
                assertEquals(listOf(first), selectRequiredGeneratedCTypes(types.reversed(), listOf("Value choose(void)")), earlier)
            }
        }
    }

    @Test
    fun `per-alias identities still reject conflicting shapes and original aggregate bodies`() {
        for ((multiple, single) in listOf(
            "typedef int Value, Other;" to "typedef long Value;",
            "typedef int Other, *Value;" to "typedef int Value;",
            "typedef int Other[3], Value[2];" to "typedef int Value[3];",
            "typedef int (*Other)(long), (*Value)(int);" to "typedef int (*Value)(long);",
            "typedef struct { int value; } Other, Value;" to "typedef struct { long value; } Value;",
            "typedef int Other, (*Value)(struct { int value; } *);" to
                "typedef int (*Value)(struct { long value; } *);",
            "typedef _Atomic(struct { int value; }) Other, Value;" to
                "typedef _Atomic(struct { long value; }) Value;",
        )) {
            val first = RecoveredType("a00_first", multiple)
            val second = RecoveredType("a10_conflict", single)
            val safe = RecoveredType("a20_safe", "typedef unsigned Safe;")
            val types = listOf(first, second, safe)
            assertEquals(listOf(safe), selectRequiredGeneratedCTypes(types, listOf("Safe choose(void)")))
            val failure = assertFailsWith<IllegalArgumentException>(multiple) {
                selectRequiredGeneratedCTypes(types, listOf("Value choose(void)"))
            }
            assertTrue(failure.message.orEmpty().contains("ambiguous recovered type dependency name:Value"), failure.message)
        }
    }

    @Test
    fun `multiple declarators preserve the selected recovered record as one evidence unit`() {
        val type = RecoveredType("aliases", "typedef int Value, *ValuePointer, Values[2];")
        assertEquals(listOf(type), selectRequiredGeneratedCTypes(listOf(type), listOf("ValuePointer get(void)")))
    }
}
