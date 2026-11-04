package decompengine.project

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class GeneratedCTypeEmissionOrderTest {
    private fun type(id: String, declaration: String) = RecoveredType(id = id, declaration = declaration)

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
            val expected = listOf(intro, body, callback)
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
        assertTrue(result.indexOf(intro) < result.indexOf(foo))
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
        assertEquals(listOf(forward, record, callback), generatedCTypeEmissionOrder(listOf(callback, record, forward)))
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
