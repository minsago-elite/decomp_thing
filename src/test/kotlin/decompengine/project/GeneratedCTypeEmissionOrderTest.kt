package decompengine.project

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class GeneratedCTypeEmissionOrderTest {
    private fun type(id: String, declaration: String) = RecoveredType(id = id, declaration = declaration)

    @Test fun `direct member expressions retain only their actual target bodies`() {
        val aliases = type("0", "typedef struct T T, *P; typedef struct Other Other, *OtherP;")
        val body = type("z", "struct T { int value; int P; };")
        val complete = listOf(
            "sizeof(((struct T *)0)->value)", "sizeof(((T *)0)->value)", "sizeof(((P)0)->value)",
            "sizeof(((((P)0)))->value)", "sizeof(*((T *)0))", "sizeof(*(P)0)",
            "sizeof((*(P)0).value)", "sizeof(((P)0)->P)", "sizeof(((P)0)->value) + 1",
            "sizeof(((void)(OtherP)0, (P)0)->value)",
            "sizeof(((void)(OtherP)0, *(P)0).value)",
        )
        for (operand in complete) {
            val user = type("a", "struct User { int values[$operand]; };")
            val input = listOf(aliases, user, body)
            for (rotation in input.indices) for (permutation in listOf(input.drop(rotation) + input.take(rotation),
                (input.drop(rotation) + input.take(rotation)).reversed())) {
                val output = generatedCTypeEmissionOrder(permutation)
                assertEquals(listOf("0", "z", "a"), output.map { it.id }, operand)
                output.forEach { record -> assertTrue(record === input.single { it.id == record.id }) }
            }
            val inventory = generatedCTypeOrderInventory(input, {}, {})
            assertEquals(setOf(COrderSymbol.Tag("T")), inventory.uses.filter {
                it.site.ownerId == "a" && it.need == COrderNeed.COMPLETE_BODY
            }.map { it.symbol }.toSet(), operand)
            val failure = assertFailsWith<IllegalArgumentException>(operand) { generatedCTypeEmissionOrder(listOf(aliases, user)) }
            assertTrue(failure.message.orEmpty().contains("COMPLETE_BODY"), failure.message)
        }
    }

    @Test fun `pointer only expressions need no body even beside unrelated member expressions`() {
        val aliases = type("0", "typedef struct T T, *P; typedef struct Other Other, *OtherP;")
        for (operand in listOf("sizeof(T *)", "_Alignof(T *)", "sizeof(P)", "_Alignof(P)",
            "sizeof((P)0)", "sizeof(((T *)0))", "sizeof(&*(P)0)", "sizeof(((void)(OtherP)0, (P)0))")) {
            val user = type("a", "struct User { int values[$operand]; };")
            val ordered = runCatching { generatedCTypeEmissionOrder(listOf(user, aliases)) }
            assertTrue(ordered.isSuccess, "pointer-only expression must admit without a body: $operand; ${ordered.exceptionOrNull()}")
            assertEquals(listOf(aliases, user), ordered.getOrThrow(), operand)
            // An invented pointer-body edge would create a cycle here.
            val body = type("z", "struct T { struct User value; };")
            assertEquals(listOf(aliases, user, body), generatedCTypeEmissionOrder(listOf(body, user, aliases)), operand)
        }
        val cast = type("a", "P pointer = (P)0;")
        assertEquals(listOf(aliases, cast), generatedCTypeEmissionOrder(listOf(cast, aliases)))
        val body = type("z", "struct T { int value; };")
        val unrelated = type("y", "struct Other { struct User value; };")
        val user = type("a", "struct User { int values[sizeof(((void)(OtherP)0, (P)0)->value)]; };")
        assertEquals(listOf(aliases, body, user, unrelated), generatedCTypeEmissionOrder(listOf(unrelated, user, aliases, body)))
    }

    @Test fun `expression aliases keep declaration scope and member names never become typedef uses`() {
        val aliases = type("0", "typedef struct T *P; typedef struct Missing Value;")
        val user = type("a", "typedef int (*Fn)(int P, int values[sizeof(((struct T *)0)->Value)]);")
        val body = type("z", "struct T { int Value; };")
        assertEquals(listOf(aliases, body, user), generatedCTypeEmissionOrder(listOf(user, body, aliases)))
        val inventory = generatedCTypeOrderInventory(listOf(aliases, user, body), {}, {})
        assertTrue(inventory.uses.none { it.site.ownerId == "a" && it.symbol == COrderSymbol.Alias("Value") })
        val renamed = type("a", "typedef int (*Fn)(int ignored, int values[sizeof(((P)0)->Value)]);")
        assertEquals(listOf(aliases, body, renamed), generatedCTypeEmissionOrder(listOf(renamed, body, aliases)))
        val shadowed = type("a", "typedef int (*Fn)(int P, int values[sizeof(((P)0)->Value)]);")
        assertTrue(assertFailsWith<IllegalArgumentException> { generatedCTypeEmissionOrder(listOf(aliases, shadowed, body)) }
            .message.orEmpty().contains("direct expression"))
        // Deferred P resolution retains its declaration's tag even when an ordinary
        // parameter shadows that tag's spelling at the expression use site.
        val nested = type("a", "typedef int (*Fn)(int T, int (*cb)(int values[sizeof(((P)0)->Value)]));")
        assertEquals(listOf(aliases, body, nested), generatedCTypeEmissionOrder(listOf(nested, body, aliases)))
        val local = type("a", "typedef int (*Fn)(struct T { int local; } *p, int values[sizeof(((P)0)->Value)]);")
        assertTrue(assertFailsWith<IllegalArgumentException> { generatedCTypeEmissionOrder(listOf(aliases, local, body)) }
            .message.orEmpty().contains("prototype tag dependency"))
        val prototypeOnly = type("a", "typedef int (*Fn)(int values[sizeof(((struct Local *)0)->value)]);")
        assertFailsWith<IllegalArgumentException> { generatedCTypeEmissionOrder(listOf(prototypeOnly, type("z", "struct Local { int value; };"))) }
    }

    @Test fun `direct parameter operands use their bound declaration shapes`() {
        val alias = type("0", "typedef struct T T, *P;")
        val body = type("z", "struct T { int value; };")
        for (parameter in listOf("T object, int values[sizeof(object)]", "P pointer, int values[sizeof(*pointer)]",
            "P pointer, int values[sizeof(pointer->value)]")) {
            val fn = type("a", "typedef int (*Fn)($parameter);")
            assertEquals(listOf(alias, body, fn), generatedCTypeEmissionOrder(listOf(fn, body, alias)))
            assertTrue(assertFailsWith<IllegalArgumentException> { generatedCTypeEmissionOrder(listOf(alias, fn)) }
                .message.orEmpty().contains("COMPLETE_BODY"))
        }
        val pointerOnly = type("a", "typedef int (*Fn)(P pointer, int values[sizeof(pointer)]);")
        assertEquals(listOf(alias, pointerOnly), generatedCTypeEmissionOrder(listOf(pointerOnly, alias)))
        val scalar = type("a", "typedef int (*Fn)(int T, int values[sizeof(T + 1)]);")
        assertEquals(listOf(alias, scalar), generatedCTypeEmissionOrder(listOf(scalar, alias)))
        val unknown = type("a", "struct User { int values[sizeof(unknown)]; };")
        assertTrue(assertFailsWith<IllegalArgumentException> { generatedCTypeEmissionOrder(listOf(alias, unknown)) }
            .message.orEmpty().contains("direct expression size operand"))
    }

    @Test fun `unproven expression targets refuse instead of silently dropping complete bodies`() {
        val aliases = type("0", "typedef struct T T, *P;")
        val body = type("z", "struct T { int value; struct T *next; };")
        for (operand in listOf("sizeof(((P)0)->next->value)", "sizeof(*(((P)0)->next))",
            "sizeof(((P)0 + 1)->value)", "sizeof((1 ? (P)0 : (P)0)->value)",
            "sizeof(((P)0)->next + 1)", "sizeof(((P)0)[0])", "sizeof(_Generic(0, int: (P)0)->value)", "sizeof(get()->value)")) {
            val user = type("a", "struct User { int values[$operand]; };")
            val failure = assertFailsWith<IllegalArgumentException>(operand) { generatedCTypeEmissionOrder(listOf(aliases, user, body)) }
            assertTrue(failure.message.orEmpty().contains("unsupported generated-C direct expression"), failure.message)
            assertTrue(failure.message.orEmpty().length < 512)
        }
    }

    @Test fun `expression traversal preserves work depth cache and cancellation guards`() {
        val alias = type("0", "typedef struct T *P;")
        val body = type("z", "struct T { int value; };")
        val grouped = type("a", "struct User { int values[sizeof(" + "(".repeat(40) + "(P)0" + ")".repeat(40) + "->value)]; };")
        // Each source group counts once; grammar helper frames do not consume depth.
        assertEquals(listOf(alias, body, grouped), generatedCTypeEmissionOrder(listOf(grouped, body, alias)))
        val nested = type("a", "struct User { int values[sizeof(" + "(".repeat(65) + "(P)0" + ")".repeat(65) + "->value)]; };")
        assertTrue(assertFailsWith<IllegalArgumentException> { generatedCTypeEmissionOrder(listOf(alias, nested, body)) }
            .message.orEmpty().contains("nesting"))
        val chain = (0..65).map { n -> type("%03d".format(n), if (n == 0) "typedef struct T *P0;" else "typedef P${n - 1} P$n;") }
        val warm = type("w", "struct Warm { int values[sizeof(*(P1)0)]; };")
        val deep = type("x", "struct Deep { int values[sizeof(*(P65)0)]; };")
        assertTrue(assertFailsWith<IllegalArgumentException> { generatedCTypeEmissionOrder(chain + listOf(warm, deep, body)) }
            .message.orEmpty().contains("depth 64"))
        val user = type("a", "struct User { int values[sizeof(((void)(P)0, (P)0)->value)]; };")
        var calls = 0
        var charged = 0L
        generatedCTypeOrderInventory(listOf(alias, user, body), { calls++ }, { charged += it })
        var interrupted = 0
        try {
            assertFailsWith<InterruptedException> {
                generatedCTypeOrderInventory(listOf(alias, user, body), {
                    if (++interrupted == calls - 20) Thread.currentThread().interrupt()
                    if (Thread.currentThread().isInterrupted) throw InterruptedException("expression cancellation")
                }, {})
            }
            assertEquals(calls - 20, interrupted)
            assertTrue(Thread.currentThread().isInterrupted)
        } finally { Thread.interrupted() }
        var budget = 0L
        assertFailsWith<IllegalArgumentException> {
            generatedCTypeOrderInventory(listOf(alias, user, body), {}, { units -> budget += units; require(budget < charged - 20) })
        }
        assertTrue(budget >= charged - 20)
    }

    @Test fun `original review regressions use direct prerequisites and retain exact records`() {
        val fixtures = listOf(
            listOf(type("a", "typedef struct A { int B; } A;"), type("b", "typedef struct B { int A; } B;")) to listOf("a", "b"),
            listOf(type("a", "struct A { struct B value; void (*callback)(void); };"), type("b", "struct B { int value; };")) to listOf("b", "a"),
            listOf(type("a", "typedef struct Complete CompleteAlias;"), type("b", "struct User { CompleteAlias *p; };"),
                type("c", "struct Complete { struct User value; };")) to listOf("a", "b", "c"),
        )
        for ((input, expected) in fixtures) for (rotation in input.indices) {
            val rotated = input.drop(rotation) + input.take(rotation)
            for (permutation in listOf(rotated, rotated.reversed())) {
                val output = generatedCTypeEmissionOrder(permutation)
                assertEquals(expected, output.map { it.id })
                output.forEach { result -> assertTrue(input.single { it.id == result.id } === result) }
                val program = RecoveredProgramModel(inputSha256 = "ordering", functions = emptyList(), types = permutation)
                val header = GeneratedCProjectRendering(program, ModulePlan(modules = emptyList())).sharedInterface()
                output.forEach { assertTrue(header.contains(it.declaration)) }
                output.zipWithNext().forEach { (a, b) -> assertTrue(header.indexOf(a.declaration) < header.indexOf(b.declaration)) }
            }
        }
    }

    @Test fun `original review paired mutations retain genuine completeness failures`() {
        val fixtures = listOf(
            listOf(type("0", "typedef struct A A; typedef struct B B;"), type("a", "struct A { B b; };"), type("b", "struct B { A a; };")),
            listOf(type("0", "struct B;"), type("a", "struct A { struct B value; void (*callback)(void); };")),
            listOf(type("a", "typedef struct Complete CompleteAlias;"), type("b", "struct User { CompleteAlias p; };"),
                type("c", "struct Complete { struct User value; };")),
        )
        fixtures.forEach { fixture ->
            val failure = assertFailsWith<IllegalArgumentException> { generatedCTypeEmissionOrder(fixture) }
            assertTrue(failure.message.orEmpty().contains("cycle") || failure.message.orEmpty().contains("COMPLETE_BODY"), failure.message)
        }
    }

    @Test fun `alias operators compose before requiring complete bodies`() {
        val aliases = type("a", "typedef struct Complete C, *P; typedef const C CC; typedef CC Alias;")
        val user = type("b", "struct User { Alias *p; P q; };")
        val body = type("c", "struct Complete { struct User value; };")
        assertEquals(listOf(aliases, user, body), generatedCTypeEmissionOrder(listOf(body, user, aliases)))
        val forward = type("0", "struct T;")
        for (array in listOf("typedef struct T *Pointers[2];", "typedef struct T *P; typedef P Pointers[2];")) {
            val pointers = type("a", array)
            val holder = type("b", "struct User { Pointers values; };")
            val complete = type("c", "struct T { struct User value; };")
            assertEquals(listOf(forward, pointers, holder, complete), generatedCTypeEmissionOrder(listOf(complete, holder, pointers, forward)))
        }
        for (array in listOf("typedef struct T (*ArrayPointer)[2];", "typedef struct T Values[];", "typedef int (*Fn)(struct T values[2]);")) {
            val use = type("a", array)
            assertFailsWith<IllegalArgumentException> { generatedCTypeEmissionOrder(listOf(forward, use)) }
            val body = type("z", "struct T { int value; };")
            assertEquals(listOf(forward, body, use), generatedCTypeEmissionOrder(listOf(use, body, forward)))
        }
        val fn = type("a", "typedef struct T Fn(struct T value); typedef Fn *Pointer;")
        val holder = type("b", "struct User { Pointer p; };")
        val complete = type("c", "struct T { struct User value; };")
        assertEquals(listOf(forward, fn, holder, complete), generatedCTypeEmissionOrder(listOf(complete, holder, fn, forward)))
    }

    @Test fun `atomic constructors distinguish their inner object from pointer targets`() {
        val forward = type("0", "struct T;")
        for (pointer in listOf("typedef _Atomic(struct T *) AP;", "typedef struct T *P; typedef _Atomic(P) AP;", "typedef struct T * _Atomic AP;")) {
            val alias = type("a", pointer)
            val holder = type("b", "struct User { AP p; };")
            val body = type("c", "struct T { struct User value; };")
            assertEquals(listOf(forward, alias, holder, body), generatedCTypeEmissionOrder(listOf(body, holder, alias, forward)))
        }
        for (aggregate in listOf("typedef _Atomic(struct T) *ATP;", "typedef _Atomic struct T *ATP;")) {
            val alias = type("a", aggregate)
            assertFailsWith<IllegalArgumentException> { generatedCTypeEmissionOrder(listOf(forward, alias)) }
            val body = type("z", "struct T { int value; };")
            assertEquals(listOf(forward, body, alias), generatedCTypeEmissionOrder(listOf(alias, body, forward)))
        }
    }

    @Test fun `expression prerequisites do not confuse members or shadowed parameter names`() {
        val base = type("z", "enum { BASE = 2 };")
        val mode = type("y", "enum Mode { COUNT = BASE + 1 };")
        val holder = type("a", "struct User { int BASE[COUNT]; unsigned bits : BASE; };")
        assertEquals(listOf(base, mode, holder), generatedCTypeEmissionOrder(listOf(holder, mode, base)))
        val packed = type("a", "struct Packed { unsigned WIDTH : WIDTH; int value; } __attribute__((packed));")
        val width = type("z", "enum { WIDTH = 3 };")
        assertEquals(listOf(width, packed), generatedCTypeEmissionOrder(listOf(packed, width)))
        val aligned = type("a", "struct User { int value; } __attribute__((aligned(BASE)));")
        assertEquals(listOf(base, aligned), generatedCTypeEmissionOrder(listOf(aligned, base)))
        val forward = type("0", "typedef struct T T;")
        for (source in listOf("enum { N = sizeof(T *) };", "struct User { _Alignas(struct T *) int value; };",
            "typedef int (*Fn)(int T, int values[sizeof(T)]);")) {
            val use = type("a", source)
            assertEquals(listOf(forward, use), generatedCTypeEmissionOrder(listOf(use, forward)))
        }
        for (source in listOf("enum { N = sizeof(T) };", "struct User { _Alignas(struct T) int value; };",
            "typedef int (*Fn)(int x, int values[sizeof(T)]);")) {
            val use = type("a", source)
            assertFailsWith<IllegalArgumentException> { generatedCTypeEmissionOrder(listOf(forward, use)) }
            val body = type("z", "struct T { int value; };")
            assertEquals(listOf(forward, body, use), generatedCTypeEmissionOrder(listOf(use, body, forward)))
        }
    }

    @Test fun `prototype identity follows actual nested scopes and declaration offsets`() {
        val body = type("z", "struct T { int value; };")
        for (source in listOf(
            "struct Holder { struct T *p; int (*cb)(struct T *); };",
            "struct Holder { struct { struct T *p; } nested; int (*cb)(struct T *); };",
            "typedef struct T (*Fn)(struct T *);",
        )) {
            val intro = type("a", source)
            assertEquals(listOf(intro, body), generatedCTypeEmissionOrder(listOf(body, intro)))
        }
        for (source in listOf(
            "struct Holder { int (*cb)(struct T *); struct T *p; };",
            "typedef int (*Fn)(int (*nested)(struct T *));",
            "typedef _Atomic(int (*)(struct T *)) Fn;",
            "typedef int (*Fn)(struct Local { struct T *p; } *);",
            "typedef int (*Fn)(struct T { int value; } *);",
        )) {
            val intro = type("a", source)
            assertTrue(assertFailsWith<IllegalArgumentException> { generatedCTypeEmissionOrder(listOf(body, intro)) }
                .message.orEmpty().contains("prototype tag dependency"))
        }
    }

    @Test fun `same record availability cannot be repaired by dropping self edges`() {
        for (source in listOf("struct T { struct T value; };",
            "enum { FIRST = LATER, LATER = 2 };")) {
            assertFailsWith<IllegalArgumentException>(source) { generatedCTypeEmissionOrder(listOf(type("a", source))) }
        }
        assertEquals(1, generatedCTypeEmissionOrder(listOf(type("a", "struct T { struct T *next; };"))).size)
    }

    @Test fun `ordering alias depth remains bounded after warming shorter suffixes`() {
        val aliases = (0..65).map { index -> type("%03d".format(index),
            if (index == 0) "typedef int T0;" else "typedef T${index - 1} T$index;") }
        assertFailsWith<IllegalArgumentException> { generatedCTypeEmissionOrder(aliases + type("zz", "struct Use { T65 value; };")) }
        assertFailsWith<IllegalArgumentException> { generatedCTypeEmissionOrder(aliases.reversed() + type("zz", "struct Use { T65 value; };")) }
        assertFailsWith<IllegalArgumentException> { generatedCTypeEmissionOrder(listOf(type("a", "typedef B A;"), type("b", "typedef A B;"))) }
    }

    @Test fun `inventory cancellation and aggregate metering are deterministic`() {
        val types = (0..20).map { type("$it", "typedef int T$it;") }
        var checks = 0
        try {
            assertFailsWith<InterruptedException> {
                generatedCTypeOrderInventory(types, {
                    if (++checks == 300) Thread.currentThread().interrupt()
                    if (Thread.currentThread().isInterrupted) throw InterruptedException("inventory test")
                }, {})
            }
            assertEquals(300, checks)
            assertTrue(Thread.currentThread().isInterrupted)
        } finally { Thread.interrupted() }
        var charged = 0L
        assertFailsWith<IllegalArgumentException> {
            generatedCTypeOrderInventory(types, {}, { units -> charged += units; require(charged <= 1000) })
        }
        assertTrue(charged > 1000)
    }

    @Test fun `sorting cancellation preserves interruption after inventory has completed`() {
        val input = (0..12).map { type("%02d".format(it), "typedef int T$it;") }
        var total = 0
        generatedCTypeEmissionOrder(input) { total++ }
        var checks = 0
        try {
            assertFailsWith<InterruptedException> {
                generatedCTypeEmissionOrder(input) { if (++checks == total - 1) Thread.currentThread().interrupt() }
            }
            assertEquals(total - 1, checks)
            assertTrue(Thread.currentThread().isInterrupted)
        } finally { Thread.interrupted() }
    }

    @Test fun `all admission graph export and nesting limits retain explicit refusals`() {
        assertFailsWith<IllegalArgumentException> { generatedCTypeEmissionOrder(listOf(type("x".repeat(4097), "typedef int T;"))) }
        assertFailsWith<IllegalArgumentException> { generatedCTypeEmissionOrder(List(65) { type("$it", " ".repeat(65_536)) }) }
        assertFailsWith<IllegalArgumentException> {
            generatedCTypeEmissionOrder(listOf(type("a", "typedef int " + "(".repeat(65) + "T" + ")".repeat(65) + ";")))
        }
        assertFailsWith<IllegalArgumentException> {
            generatedCTypeEmissionOrder(listOf(type("a", "struct A { " + "struct { ".repeat(65) + "int x;" + "} v;".repeat(65) + "};")))
        }
        val names = (0 until 260).map { "${('a'.code + it / 26).toChar()}${('a'.code + it % 26).toChar()}" }
        val dense = names.mapIndexed { index, name -> type("%03d".format(index),
            "enum { $name = " + names.filter { it != name }.joinToString("+") + " };") }
        val edges = assertFailsWith<IllegalArgumentException> { generatedCTypeEmissionOrder(dense) }
        assertTrue(edges.message.orEmpty().contains("edges exceed"), edges.message)
        val manyExports = (0 until 66).map { record -> type("%03d".format(record), "enum { " +
            (0 until 2000).joinToString(",") { "E" + (record * 2000 + it).toString(36) } + " };") }
        val exports = assertFailsWith<IllegalArgumentException> { generatedCTypeEmissionOrder(manyExports) }
        assertTrue(exports.message.orEmpty().contains("inventory exceeds its bound"), exports.message)
    }

    @Test fun `ordinary prototype enumerators shadow typedefs only after their declaration`() {
        val alias = type("0", "typedef struct T T;")
        val local = type("a", "typedef int (*Fn)(enum { T = 2 } value, int values[sizeof(T)]);")
        assertEquals(listOf(alias, local), generatedCTypeEmissionOrder(listOf(local, alias)))
        val renamed = type("a", "typedef int (*Fn)(enum { V = 2 } value, int values[sizeof(T)]);")
        assertFailsWith<IllegalArgumentException> { generatedCTypeEmissionOrder(listOf(alias, renamed)) }
        val early = type("a", "typedef int (*Fn)(int values[sizeof(T)], enum { T = 2 } value);")
        assertFailsWith<IllegalArgumentException> { generatedCTypeEmissionOrder(listOf(alias, early)) }
    }

    @Test fun `cached alias suffixes cannot reduce the completeness depth requirement`() {
        val aliases = (0..65).map { index -> type("%03d".format(index),
            (if (index == 0) "typedef int T0;" else "typedef T${index - 1} T$index;") + " struct Use$index { T$index value; };") }
        val error = assertFailsWith<IllegalArgumentException> { generatedCTypeEmissionOrder(aliases) }
        assertTrue(error.message.orEmpty().contains("depth 64"), error.message)
    }

    @Test fun `aggregate work meter spans many independently admitted small records`() {
        val input = (0 until 80).map { record -> type("%03d".format(record),
            "typedef struct { " + (0 until 100).joinToString(" ") { "int v$it;" } + " } " +
                (0 until 250).joinToString(",") { "A${record}_$it" } + ";") }
        val text = input.sumOf { it.id.length.toLong() + it.declaration.length }
        assertTrue(input.all { it.declaration.length < 4096 })
        assertTrue(text * input.size <= 64L * 1024 * 1024)
        val failure = assertFailsWith<IllegalArgumentException> { generatedCTypeEmissionOrder(input) }
        assertTrue(failure.message.orEmpty().contains("inventory work exceeds"), failure.message)
    }

    @Test fun `bounded type operands use original anonymous bodies and compound literal dependencies`() {
        val type = type("z", "typedef int Element;")
        val extent = type("a", "enum { N = sizeof(struct { Element field; }) };")
        assertEquals(listOf(type, extent), generatedCTypeEmissionOrder(listOf(extent, type)))
        val alias = type("0", "typedef struct T T;")
        val literal = type("a", "enum { N = sizeof((T){0}) };")
        val body = type("z", "struct T { int value; };")
        assertEquals(listOf(alias, body, literal), generatedCTypeEmissionOrder(listOf(literal, body, alias)))
        assertFailsWith<IllegalArgumentException> { generatedCTypeEmissionOrder(listOf(alias, literal)) }
    }

    @Test fun `opposite alias identities and repeated sibling shapes preserve direct dependencies`() {
        val aliases = type("z", "typedef struct Complete C, *P; typedef const C CC; typedef CC Alias;")
        val user = type("a", "struct User { Alias *p; P q; };")
        val body = type("b", "struct Complete { struct User value; };")
        assertEquals(listOf(aliases, user, body), generatedCTypeEmissionOrder(listOf(user, aliases, body)))
        val first = type("a", "typedef int Other, *Value;")
        val equivalent = type("b", "typedef int *Value;")
        assertEquals(listOf(first, equivalent), generatedCTypeEmissionOrder(listOf(equivalent, first)))
        val changed = type("b", "typedef int Value[2];")
        assertFailsWith<IllegalArgumentException> { generatedCTypeEmissionOrder(listOf(first, changed)) }
    }

    @Test fun `comment and literal scans propagate interruption during charged token work`() {
        for (source in listOf("/*" + "x".repeat(60000) + "*/ typedef int T;",
            "enum { N = sizeof(\"" + "x".repeat(60000) + "\") };")) {
            var steps = 0
            try {
                assertFailsWith<InterruptedException> {
                    generatedCTypeOrderInventory(listOf(type("a", source)), {
                        if (Thread.currentThread().isInterrupted) throw InterruptedException("scan cancelled")
                    }, { units -> if (units == 1L && ++steps == 1500) Thread.currentThread().interrupt() })
                }
                assertEquals(1500, steps)
                assertTrue(Thread.currentThread().isInterrupted)
            } finally { Thread.interrupted() }
        }
        val warm = type("0", "typedef int Scalar; struct Warm { Scalar value; };")
        val cycle = type("a", "typedef B A; typedef A B; struct Use { A value; };")
        assertTrue(assertFailsWith<IllegalArgumentException> { generatedCTypeEmissionOrder(listOf(warm, cycle)) }
            .message.orEmpty().contains("cycle"))
    }

    @Test fun `aliases fields and enums precede users regardless of hashed IDs or iteration`() {
        val scalar = type("type_z", "  typedef unsigned long word;\n")
        val enumeration = type("type_y", "typedef enum Kind { ZERO = 0, FIRST = 1 } Kind;")
        val record = type("type_a", "typedef struct Record { word value; Kind kind; char label[16]; } Record;")
        val alias = type("type_0", "typedef Record RecordAlias;")
        val input = listOf(alias, record, scalar, enumeration)
        val expected = listOf(enumeration, scalar, record, alias)
        for (rotation in input.indices) {
            val permuted = input.drop(rotation) + input.take(rotation)
            assertEquals(expected, generatedCTypeEmissionOrder(permuted))
            assertEquals(expected, generatedCTypeEmissionOrder(permuted.reversed()))
        }
        assertEquals("  typedef unsigned long word;\n", generatedCTypeEmissionOrder(input)[1].declaration)
    }

    @Test fun `actual self tag reference does not create an ordering cycle`() {
        val node = type("n", "typedef struct Node { struct Node *next; int value; } Node;")
        assertEquals(listOf(node), generatedCTypeEmissionOrder(listOf(node)))
    }

    @Test fun `authentic standalone tag forwards precede definitions without false cycles`() {
        val forward = type("z", "struct Node;")
        val definition = type("a", "struct Node { int value; };")
        assertEquals(listOf(forward, definition), generatedCTypeEmissionOrder(listOf(definition, forward)))
        assertEquals(listOf(forward, definition), generatedCTypeEmissionOrder(listOf(forward, definition)))
    }

    @Test fun `file scope typedef and member introductions do not require later bodies`() {
        for (introduction in listOf(
            "typedef struct Foo FooAlias;",
            "struct Holder { struct Foo *p; };",
            "struct Holder { struct Nested { struct Foo *p; } nested; };",
        )) {
            val intro = type("a00_intro", introduction)
            val callback = type("a10_callback", "typedef int (*Fn)(struct Foo *);")
            val body = type("a20_definition", "struct Foo { int value; };")
            val expected = listOf(intro, callback, body)
            assertEquals(expected, generatedCTypeEmissionOrder(listOf(intro, callback, body)))
            assertEquals(expected, generatedCTypeEmissionOrder(listOf(body, callback, intro)))
            assertEquals(introduction, expected.first().declaration)
        }
    }

    @Test fun `pointer introductions retain independent by value and alias prerequisites`() {
        val scalar = type("z_scalar", "typedef long Word;")
        val complete = type("z_complete", "struct Complete { Word value; };")
        val intro = type("a_intro", "struct Holder { struct Foo *p; struct Complete value; Word count; };")
        val foo = type("b_foo", "struct Foo { int value; };")
        val result = generatedCTypeEmissionOrder(listOf(intro, foo, complete, scalar))
        assertTrue(result.indexOf(scalar) < result.indexOf(complete))
        assertTrue(result.indexOf(complete) < result.indexOf(intro))
        val alias = type("a_alias", "typedef struct Complete CompleteAlias;")
        val user = type("b_user", "struct User { CompleteAlias value; };")
        val byValue = generatedCTypeEmissionOrder(listOf(user, alias, complete, scalar))
        assertTrue(byValue.indexOf(complete) < byValue.indexOf(user))
        assertTrue(byValue.indexOf(alias) < byValue.indexOf(user))
    }

    @Test fun `mutual member pointer introductions preserve original file scope order`() {
        val holder = type("a", "struct Holder { struct Foo *p; };")
        val foo = type("b", "struct Foo { struct Holder *p; };")
        assertEquals(listOf(holder, foo), generatedCTypeEmissionOrder(listOf(foo, holder)))
        val mixed = type("a", "struct Holder { struct Foo *p; struct Foo value; };")
        val complete = type("b", "struct Foo { int value; };")
        assertEquals(listOf(complete, mixed), generatedCTypeEmissionOrder(listOf(mixed, complete)))
    }

    @Test fun `ordering cannot turn prototype local tags into file scope identities`() {
        val callback = type("a", "typedef int (*Callback)(struct Record *);")
        val record = type("b", "struct Record { int value; };")
        val error = assertFailsWith<IllegalArgumentException> { generatedCTypeEmissionOrder(listOf(callback, record)) }
        assertTrue(error.message.orEmpty().contains("prototype tag dependency"))
        val forward = type("0", "struct Record;")
        assertEquals(listOf(forward, callback, record), generatedCTypeEmissionOrder(listOf(callback, record, forward)))
    }

    @Test fun `shared header preserves retained declaration bytes`() {
        val declaration = "  typedef unsigned long Word; \n"
        val model = RecoveredProgramModel(inputSha256 = "test", functions = emptyList(), types = listOf(type("word", declaration)))
        val header = GeneratedCProjectRendering(model, ModulePlan(modules = emptyList())).sharedInterface()
        assertTrue(declaration in header)
    }

    @Test fun `unresolved mutual dependencies fail explicitly`() {
        val error = assertFailsWith<IllegalArgumentException> {
            generatedCTypeEmissionOrder(listOf(type("a", "typedef B A;"), type("b", "typedef A B;")))
        }
        assertTrue(error.message.orEmpty().contains("cycle"))
    }

    @Test fun `incompatible namespace definitions fail before ordering`() {
        assertFailsWith<IllegalArgumentException> {
            generatedCTypeEmissionOrder(listOf(type("a", "typedef long Word;"), type("b", "typedef int Word;")))
        }
        assertFailsWith<IllegalArgumentException> {
            generatedCTypeEmissionOrder(listOf(type("a", "struct Record { int a; };"), type("b", "struct Record { long a; };")))
        }
    }

    @Test fun `inventory text and repeated selector work are bounded before tokenization`() {
        assertFailsWith<IllegalArgumentException> { generatedCTypeEmissionOrder(List(4097) { type("$it", "typedef int T$it;") }) }
        assertFailsWith<IllegalArgumentException> { generatedCTypeEmissionOrder(listOf(type("a", " ".repeat(65_537)))) }
        assertFailsWith<IllegalArgumentException> { generatedCTypeEmissionOrder(List(300) { type("$it", " ".repeat(1000)) }) }
        assertFailsWith<IllegalArgumentException> { generatedCTypeEmissionOrder(listOf(type("a", "typedef int A;"), type("a", "typedef int A;"))) }
    }

    @Test fun `cancellation propagates without consuming interrupt`() {
        Thread.currentThread().interrupt()
        try {
            assertFailsWith<InterruptedException> { generatedCTypeEmissionOrder(emptyList()) }
            assertTrue(Thread.currentThread().isInterrupted)
        } finally { Thread.interrupted() }
    }
}
