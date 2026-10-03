package decompengine.oracle.structural

import decompengine.oracle.core.OracleJson
import decompengine.oracle.fulltree.BoundedDwarfInterfaceFacts
import decompengine.oracle.fulltree.DwarfGlobalVariableFacts
import decompengine.oracle.fulltree.DwarfInterfaceFact
import decompengine.oracle.fulltree.DwarfInterfaceFactState
import decompengine.oracle.fulltree.DwarfInterfaceFunctionFacts
import decompengine.oracle.fulltree.DwarfInterfaceParameterFacts
import decompengine.oracle.fulltree.DwarfInterfaceParameterList
import decompengine.oracle.fulltree.DwarfInterfaceTypeChild
import decompengine.oracle.fulltree.DwarfInterfaceTypeNode
import decompengine.oracle.fulltree.inInterfaceFixtureDirectory
import decompengine.oracle.fulltree.scanInterfaceFixture
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.JsonNull
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DwarfSysvAmd64InterfaceProjectionTest {
    @Test
    fun `proved C prototype applies documented void convention and nonvariadic defaults`() {
        val function = function(returned = absent(), parameters = emptyList())
        val projected = project(function).functions.single()
        assertTrue(projected.fullyObservable, projected.reasons.toString())
        assertEquals("sysv-amd64", projected.callingConvention)
        assertEquals(0, projected.arity)
        assertEquals(false, projected.variadic)
        assertEquals(DwarfAbiScalarKind.VOID, projected.returnType?.shape?.scalar)
        assertEquals(DwarfAbiPassing.NONE, projected.returnType?.classification?.returnPassing)
        assertTrue(projected.evidence.any { it.contains("no-return-type-void") })

        val scalar = project(function(parameters = listOf(parameter("int"))), intType).functions.single()
        assertTrue(scalar.fullyObservable, scalar.reasons.toString())
        assertEquals(listOf(DwarfAbiClass.INTEGER), scalar.parameters.single()?.classification?.classes)
        assertEquals(listOf(DwarfAbiClass.INTEGER), scalar.returnType?.classification?.classes)
    }

    @Test
    fun `unsupported prototype language convention and inheritance never manufacture complete signatures`() {
        val unprototyped = project(function(prototyped = absent()), intType).functions.single()
        assertFalse(unprototyped.fullyObservable)
        assertNull(unprototyped.arity)
        assertNull(unprototyped.variadic)
        val cpp = project(function(language = known("33"), prototyped = absent()), intType).functions.single()
        assertTrue(cpp.fullyObservable, cpp.reasons.toString())
        listOf(
            function(language = absent()),
            function(language = known("8")),
            function(convention = known("2")),
            function(convention = unknown()),
            function(declaration = known("1")),
            function(declaration = unknown()),
            function(reasons = listOf("origin-specification-cycle")),
            function(reasons = listOf("unsupported-function-ABI-attribute:static-link")),
            function(returned = ambiguous("int", "other")),
            function(variadic = unknown()),
            function(sequence = ambiguous("function", "other-function")),
            function(parameters = listOf(parameter("int", ordinal = 1))),
        ).forEach { input ->
            assertFalse(project(input, intType).functions.single().fullyObservable, input.locator)
        }
        val inherited = project(function(sequence = DwarfInterfaceFact(
            DwarfInterfaceFactState.KNOWN, listOf("declaration"), listOf("definition", "declaration"),
            listOf("parameter-sequence-inherited"),
        )), intType).functions.single()
        assertTrue(inherited.fullyObservable, inherited.reasons.toString())
    }

    @Test
    fun `origin sequence reconciliation requires exact proved qualifier roots and matching varargs`() {
        val qualified = node("qualified", 0x26, referenced = known("int"))
        val alias = node("alias", 0x16, referenced = known("qualified"))
        val unrelated = node("other-int", 0x24, size = known("4"), encoding = known("5"))
        val atomic = node("atomic", 0x47, referenced = known("int"))
        val conflict = node("conflict", 0x26, size = known("8"), referenced = known("int"))
        val cycle = node("cycle", 0x16, referenced = known("cycle"))
        fun candidate(first: String, second: String, secondVariadic: DwarfInterfaceFact<Boolean> = absent()): DwarfInterfaceFunctionFacts {
            val selected = listOf(parameter(first))
            val reason = listOf("concrete-and-inherited-parameter-sequences-differ")
            return function(parameters = selected,
                sequence = DwarfInterfaceFact(DwarfInterfaceFactState.AMBIGUOUS, listOf("function"),
                    listOf("function", "declaration"), reason),
                variadic = DwarfInterfaceFact(DwarfInterfaceFactState.AMBIGUOUS, reasons = reason),
                lists = listOf(DwarfInterfaceParameterList("function", selected, absent()),
                    DwarfInterfaceParameterList("declaration", listOf(parameter(second)), secondVariadic)))
        }
        val types = arrayOf(intType, qualified, alias, unrelated, atomic, conflict, cycle)
        val positiveRaw = candidate("alias", "int")
        val positive = project(positiveRaw, *types).functions.single()
        assertEquals(DwarfInterfaceFactState.AMBIGUOUS, positiveRaw.parameterList.state)
        assertTrue(positive.fullyObservable, positive.reasons.toString())
        assertEquals(1, positive.arity)
        assertEquals(false, positive.variadic)
        assertTrue(positive.evidence.any { it.contains("exact-alias-qualifier-root-equivalence") })
        listOf(candidate("alias", "other-int"), candidate("alias", "int", known(true)),
            candidate("atomic", "int"), candidate("conflict", "int"), candidate("cycle", "int")).forEach { raw ->
            val projected = project(raw, *types).functions.single()
            assertFalse(projected.fullyObservable)
            assertNull(projected.arity)
            assertNull(projected.variadic)
        }
    }

    @Test
    fun `scalar representations aliases and pointer defaults preserve known and unknown distinctions`() {
        assertUnknownType(node("atomic", 0x47, referenced = known("int")), intType)
        val pointer = node("pointer", 0x0f)
        val alias = node("alias", 0x16, referenced = known("int"))
        val precise = listOf(
            pointer to DwarfAbiScalarKind.POINTER,
            alias to DwarfAbiScalarKind.INTEGER,
            node("half", 0x24, size = known("2"), encoding = known("4")) to DwarfAbiScalarKind.FLOAT16,
            node("extended", 0x24, name = known("long double"), size = known("16"), encoding = known("4")) to DwarfAbiScalarKind.X87,
            node("quad", 0x24, name = known("__float128"), size = known("16"), encoding = known("4")) to DwarfAbiScalarKind.FLOAT128,
        )
        precise.forEach { (type, kind) ->
            val result = assertNotNull(project(function(returned = known(type.id)), intType, type).functions.single().returnType)
            assertTrue(result.observable, result.reasons.toString())
            assertEquals(kind, result.shape?.scalar)
        }
        listOf(
            node("bad-pointer", 0x0f, size = known("4")),
            node("ambiguous-float", 0x24, size = known("16"), encoding = known("4")),
            node("bad-boolean", 0x24, size = known("4"), encoding = known("2")),
            node("missing-encoding", 0x24, size = known("4")),
            node("bad-integer", 0x24, size = known("18446744073709551615"), encoding = known("5")),
            node("negative-integer", 0x24, size = known("-1"), encoding = known("5")),
            node("padded-integer", 0x24, size = known("04"), encoding = known("5")),
            node("alias-conflict", 0x16, size = known("8"), referenced = known("int")),
            node("alignment-conflict", 0x24, size = known("4"), encoding = known("5"), attributes = mapOf(0x88L to known("8"))),
        ).forEach { assertUnknownType(it, intType) }
        val recursive = node("recursive", 0x16, referenced = known("recursive"))
        assertUnknownType(recursive)
        // A pointer is terminal: lack of a pointee definition does not erase its proved LP64 width.
        val terminal = node("terminal", 0x0f, referenced = known("missing-pointee"))
        assertTrue(project(function(returned = known(terminal.id)), terminal).functions.single().returnType!!.observable)
    }

    @Test
    fun `proved aggregate members classify but unknown declaration and virtuality stay unknown`() {
        val pair = aggregate("pair", 16, 8, listOf(member("tag", "int", 0), member("value", "double", 8)))
        val result = project(function(returned = known("pair")), pair, intType, doubleType).functions.single().returnType!!
        assertTrue(result.observable, result.reasons.toString())
        assertEquals(listOf(DwarfAbiClass.INTEGER, DwarfAbiClass.SSE), result.classification?.classes)
        assertUnknownType(node("unproved-alignment", 0x13, size = known("8")))
        assertUnknownType(aggregate("unknown-declaration", 4, 4, listOf(member("field", "int", 0)),
            extra = mapOf(0x3cL to unknown())), intType)
        assertUnknownType(aggregate("declaration", 4, 4, listOf(member("field", "int", 0)),
            extra = mapOf(0x3cL to known("1"))), intType)
        val baseType = aggregate("base-type", 4, 4, listOf(member("value", "int", 0)), extra = mapOf(0x36L to known("5")))
        val base = child("base", 0x1c, "base-type", mapOf(0x38L to known("0"), 0x4cL to unknown()))
        val derived = aggregate("derived", 4, 4, listOf(base), extra = mapOf(0x36L to known("5")))
        val cpp = project(function(returned = known("derived"), language = known("33")), derived, baseType, intType)
        assertFalse(cpp.functions.single().returnType!!.observable)
        assertUnknownType(aggregate("unknown-member-storage", 4, 4, listOf(child("field", 0x0d, "int",
            mapOf(0x38L to known("0"), 0x3fL to unknown())))), intType)
        val nontrivial = aggregate("nontrivial", 128, 8, emptyList(), extra = mapOf(0x36L to known("4")))
        val indirect = project(function(returned = known("nontrivial"), language = known("33")), nontrivial)
            .functions.single().returnType!!
        assertTrue(indirect.observable)
        assertEquals(DwarfAbiPassing.INVISIBLE_REFERENCE, indirect.classification?.returnPassing)
        val unprovedCpp = project(function(returned = known("pair"), language = known("33")), pair, intType, doubleType)
        assertFalse(unprovedCpp.functions.single().returnType!!.observable)
    }

    @Test
    fun `aggregate size incompatible with alignment leaves both parameter and return ABI unknown`() {
        val impossible = aggregate("size-four-align-eight", 4, 8, listOf(member("field", "int", 0)))
        val projected = project(function(returned = known(impossible.id),
            parameters = listOf(parameter(impossible.id))), impossible, intType).functions.single()
        assertFalse(projected.fullyObservable)
        assertFalse(projected.returnType!!.observable)
        assertFalse(projected.parameters.single()!!.observable)
        assertTrue(projected.returnType!!.reasons.any { it.contains("aggregate-size-is-not-multiple-of-alignment") })
        assertTrue(projected.parameters.single()!!.reasons.any { it.contains("aggregate-size-is-not-multiple-of-alignment") })
        assertUnknownType(aggregate("zero-alignment", 4, 0, listOf(member("field", "int", 0))), intType)
    }

    @Test
    fun `compiled aligned typedef stays observable while unsupported typedef over-alignment stays unresolved`() =
        inInterfaceFixtureDirectory { root ->
            val artifact = compile(root, "aligned-typedef.c", """
                typedef struct __attribute__((aligned(16))) SupportedAligned {
                    int value;
                } SupportedAligned;
                typedef struct PlainRecord { int value; } PlainRecord;
                typedef PlainRecord UnsupportedOverAligned __attribute__((aligned(16)));
                __attribute__((noinline,used)) SupportedAligned supported(SupportedAligned value) { return value; }
                __attribute__((noinline,used)) UnsupportedOverAligned unsupported(UnsupportedOverAligned value) { return value; }
                int main(void) {
                    SupportedAligned supported_value = { 1 };
                    UnsupportedOverAligned unsupported_value = { 2 };
                    return supported(supported_value).value + unsupported(unsupported_value).value;
                }
            """.trimIndent())
            val facts = scanInterfaceFixture(artifact, root)
            val supportedAlias = facts.types.values.single { it.tag == 0x16L && "SupportedAligned" in it.name.values }
            assertEquals(listOf("16"), supportedAlias.attributes.getValue(0x88L).values)
            val supportedAggregate = facts.types.getValue(supportedAlias.type.values.single())
            assertEquals(0x13L, supportedAggregate.tag)
            assertEquals(listOf("16"), supportedAggregate.byteSize.values)
            assertEquals(listOf("16"), supportedAggregate.attributes.getValue(0x88L).values)

            val projected = DwarfSysvAmd64InterfaceProjection.project(facts, target())
            val supported = projectedFunction(facts, projected, "supported")
            assertTrue(supported.fullyObservable, supported.reasons.toString())
            assertTrue(supported.returnType!!.observable)
            assertEquals(16L, supported.returnType!!.shape?.alignmentBytes)
            assertTrue(supported.parameters.single()!!.observable)
            assertEquals(16L, supported.parameters.single()!!.shape?.alignmentBytes)

            val unsupportedAlias = facts.types.values.single { it.tag == 0x16L && "UnsupportedOverAligned" in it.name.values }
            assertEquals(listOf("16"), unsupportedAlias.attributes.getValue(0x88L).values)
            val unsupported = projectedFunction(facts, projected, "unsupported")
            assertFalse(unsupported.fullyObservable)
            assertFalse(unsupported.returnType!!.observable)
            assertFalse(unsupported.parameters.single()!!.observable)
        }

    @Test
    fun `validated static qualifier and imported children preserve instance ABI and every raw fact`() {
        val deferred = DwarfInterfaceFact(DwarfInterfaceFactState.KNOWN, listOf("unexpanded-static-type"),
            listOf("static:attribute=0x49"), listOf("type-reference-not-expanded:abi-layout-non-layout-child"))
        val children = listOf(
            member("field", "int", 0),
            nonInstance("static-declaration", 0x34, deferred, mapOf(0x3cL to known("1"))),
            // A static definition need not have declaration/external=true or a known location.
            nonInstance("static-definition", 0x34, deferred, mapOf(0x02L to unknown("uninterpreted-static-location"))),
            nonInstance("using-declaration", 0x08, absent(), mapOf(0x18L to known("unexpanded-base-member"))),
        ) + listOf(0x26L, 0x35L, 0x37L, 0x47L).map { tag ->
            nonInstance("qualifier-$tag", tag, DwarfInterfaceFact(DwarfInterfaceFactState.KNOWN,
                listOf("record"), listOf("qualifier-$tag:attribute=0x49"), listOf("type-reference-cycle:record")))
        }
        val record = aggregate("record", 4, 4, children, extra = mapOf(0x36L to known("5")))
        val original = record.toJson()
        val projected = project(function(returned = known(record.id), parameters = listOf(parameter(record.id)),
            language = known("33")), record, intType)
        val function = projected.functions.single()
        assertTrue(function.fullyObservable, function.reasons.toString())
        assertEquals(listOf(DwarfAbiClass.INTEGER), function.returnType?.classification?.classes)
        assertEquals(1, function.returnType?.shape?.fields?.size)
        assertEquals(original, record.toJson())
        assertEquals(children.map { it.toJson() }, record.children.map { it.toJson() })
        assertTrue(projected.types.none { it.rawTypeId in setOf("unexpanded-static-type", "unexpanded-base-member") })
        assertTrue(projected.ruleProfile.getValue("nonInstanceChildRules").toString().contains("validated-import-reference"))
    }

    @Test
    fun `noninstance declarations reject malformed references inheritance and instance layout evidence`() {
        val unsupported = listOf(
            nonInstance("missing-type", 0x34, absent()),
            nonInstance("unknown-type", 0x26, unknown()),
            nonInstance("ambiguous-type", 0x35, ambiguous("int", "other")),
            nonInstance("unrelated-cycle", 0x26, DwarfInterfaceFact(DwarfInterfaceFactState.KNOWN,
                listOf("int"), reasons = listOf("type-reference-cycle:other"))),
            nonInstance("conflicting-type", 0x34, known("int"), mapOf(0x49L to known("other"))),
            nonInstance("unknown-declaration", 0x34, known("int"), mapOf(0x3cL to unknown())),
            nonInstance("origin-cycle", 0x34, known("int"), reasons = listOf("origin-specification-cycle")),
            nonInstance("nested-child", 0x26, known("int"), reasons = listOf("nested-type-child-children-unrepresented:nested-child")),
            nonInstance("wrong-capture-warning", 0x34, known("int"), reasons = listOf("unsupported-type-child-tag:0x26")),
            nonInstance("missing-import", 0x08, absent()),
            nonInstance("unknown-import", 0x08, absent(), mapOf(0x18L to unknown())),
            nonInstance("ambiguous-import", 0x08, absent(), mapOf(0x18L to ambiguous("one", "two"))),
            nonInstance("import-with-type", 0x08, known("int"), mapOf(0x18L to known("target"))),
            nonInstance("import-with-raw-type", 0x08, absent(), mapOf(0x18L to known("target"), 0x49L to known("int"))),
            nonInstance("unknown-tag", 0x777, known("int")),
        ) + listOf(0x38L, 0x0cL, 0x0dL, 0x6bL).flatMap { attribute ->
            listOf(known("0"), unknown<String>()).mapIndexed { index, value ->
                nonInstance("instance-layout-$attribute-$index", 0x34, known("int"), mapOf(attribute to value))
            }
        }
        unsupported.forEach { child ->
            assertUnknownType(aggregate("record-${child.id}", 4, 4, listOf(member("field", "int", 0), child)), intType)
        }
    }

    @Test
    fun `neutral declarations cannot hide unknown member base or atomic instance layout`() {
        val static = nonInstance("static", 0x34, known("int"))
        val atomic = node("atomic", 0x47, referenced = known("int"))
        val uncertain = listOf(
            child("missing-offset", 0x0d, "int", emptyMap()),
            child("missing-member-type", 0x0d, "missing", mapOf(0x38L to known("0"))),
            child("unknown-offset", 0x0d, "int", mapOf(0x38L to unknown())),
            child("base-without-offset", 0x1c, "int", emptyMap()),
            child("virtual-base", 0x1c, "int", mapOf(0x38L to known("0"), 0x4cL to known("1"))),
            member("atomic-instance", "atomic", 0),
        )
        uncertain.forEach { field ->
            assertUnknownType(aggregate("record-${field.id}", 4, 4, listOf(field, static)), intType, atomic)
        }
    }

    @Test
    fun `array counts strides dimensions and vector markers cannot change proved representation`() {
        val array = node("array", 0x01, referenced = known("int"), children = listOf(dimension("dimension", upper = "1")))
        val result = project(function(returned = known("array")), array, intType).functions.single().returnType!!
        assertTrue(result.observable)
        assertEquals(8L, result.shape?.byteSize)
        assertEquals(listOf(DwarfAbiClass.INTEGER), result.classification?.classes)
        listOf(
            node("conflicting-count", 0x01, referenced = known("int"), children = listOf(dimension("dimension", upper = "1", count = "3"))),
            node("negative-count", 0x01, referenced = known("int"), children = listOf(dimension("dimension", count = "-1"))),
            node("oversized-count", 0x01, referenced = known("int"), children = listOf(dimension("dimension", count = "1000001"))),
            node("oversized-product", 0x01, referenced = known("int"), children = listOf(dimension("x", count = "1000"), dimension("y", count = "1001"))),
            node("stride", 0x01, referenced = known("int"), attributes = mapOf(0x51L to known("8")), children = listOf(dimension("dimension", count = "2"))),
            node("bad-size", 0x01, size = known("16"), referenced = known("int"), children = listOf(dimension("dimension", count = "2"))),
            node("gnu-vector", 0x01, referenced = known("float"), attributes = mapOf(0x2107L to unknown("uninterpreted-type-attribute:0x2107")),
                children = listOf(dimension("dimension", count = "4"))),
        ).forEach { assertUnknownType(it, intType, floatType) }
    }

    @Test
    fun `bitfields check storage proof bounds and legacy container size before claiming classes`() {
        val valid = aggregate("bitfield", 4, 4, listOf(child("bits", 0x0d, "int", mapOf(
            0x38L to known("0"), 0x0dL to known("4"), 0x6bL to known("3"),
        ))))
        val projected = project(function(returned = known(valid.id)), valid, intType).functions.single().returnType!!
        assertTrue(projected.observable, projected.reasons.toString())
        assertEquals(listOf(DwarfAbiClass.INTEGER), projected.classification?.classes)
        val invalidFields = listOf(
            mapOf(0x0dL to known("4"), 0x6bL to known("3")),
            mapOf(0x38L to known("0"), 0x0dL to known("33"), 0x6bL to known("0")),
            mapOf(0x38L to known("0"), 0x0dL to known("4"), 0x6bL to known("0"), 0x0cL to known("0")),
            mapOf(0x38L to known("0"), 0x0dL to known("4"), 0x0cL to known("4"), 0x0bL to known("1")),
            mapOf(0x38L to known("0"), 0x0dL to known("4"), 0x0cL to known("4"), 0x0bL to unknown()),
        )
        invalidFields.forEachIndexed { index, attributes ->
            assertUnknownType(aggregate("bad-bitfield-$index", 8, 4, listOf(child("bits", 0x0d, "int", attributes))), intType)
        }
    }

    @Test
    fun `closed target mutation and duplicate identities fail while projection snapshots stay immutable`() {
        val target = target()
        val changed = JsonObject(target + ("scalarWidthsBits" to JsonObject(
            (target.getValue("scalarWidthsBits") as JsonObject) + ("pointer" to JsonPrimitive(32)),
        )))
        assertFailsWith<IllegalArgumentException> { DwarfSysvAmd64InterfaceProjection.project(listOf(function()), mapOf("int" to intType), changed) }
        assertFailsWith<IllegalArgumentException> { DwarfSysvAmd64InterfaceProjection.project(listOf(function(), function()), mapOf("int" to intType), target) }
        val projected = project(function(), intType)
        assertEquals("dwarf-sysv-amd64-lp64-projection-v3", DwarfSysvAmd64InterfaceProjection.VERSION)
        assertEquals(64, projected.ruleProfileSha256.length)
        assertEquals("021b9e246e8c0cd250dbd660e03b0baba41338ba4c23e0fe4831fc11570c35df", projected.ruleProfileSha256)
        assertFailsWith<UnsupportedOperationException> { (projected.functions as MutableList<*>).clear() }
        assertFailsWith<UnsupportedOperationException> { (projected.types as MutableList<*>).clear() }
        assertEquals(projected.ruleProfileSha256, project(function(), intType).ruleProfileSha256)
    }

    @Test
    fun `global-only declared types expand without inventing automatic or unknown-language types`() {
        val globals = listOf(
            global("global-only", "int"),
            global("automatic", "unexpanded", storage = known("automatic")),
            global("unknown-language", "int", language = unknown()),
        )
        val projected = DwarfSysvAmd64InterfaceProjection.project(emptyList(), mapOf("int" to intType), target(), globals)
        assertTrue(projected.functions.isEmpty())
        val declared = projected.types.single()
        assertEquals("29:int", declared.id)
        assertTrue(declared.observable)
        val rows = projected.globals.associateBy { it.getValue("locator") }
        val positive = rows.getValue(JsonPrimitive("global-only"))
        assertEquals(JsonPrimitive("29:int"), positive["projectedTypeId"])
        assertEquals(JsonPrimitive(true), positive["observableDeclaredTypeAbi"])
        listOf("automatic", "unknown-language").forEach { name ->
            val row = rows.getValue(JsonPrimitive(name))
            assertEquals(JsonNull, row["projectedTypeId"])
            assertEquals(JsonPrimitive(false), row["observableDeclaredTypeAbi"])
        }
        assertTrue(rows.getValue(JsonPrimitive("automatic")).getValue("reasons").toString().contains("unexpanded"))
        assertFailsWith<UnsupportedOperationException> { (projected.globals as MutableList<*>).clear() }
    }

    @Test
    fun `compiled C projects scalar void variadic and aligned aggregate while retaining vector uncertainty`() =
        inInterfaceFixtureDirectory { root ->
            val artifact = compile(root, "interfaces.c", """
                #include <stdarg.h>
                typedef struct __attribute__((aligned(8))) Pair { long key; double value; } Pair;
                typedef float FloatVector __attribute__((vector_size(16)));
                unsigned short global_only = 7;
                __attribute__((noinline,used)) long scalar(long value, int count) { return value + count; }
                __attribute__((noinline,used)) Pair pair(Pair value) { value.key++; return value; }
                __attribute__((noinline,used)) FloatVector vector(FloatVector value) { return value; }
                __attribute__((noinline,used)) void no_return(void) {}
                __attribute__((noinline,used)) double variadic(int count, ...) {
                    va_list args; va_start(args, count);
                    double value = count ? va_arg(args, double) : 0.0; va_end(args); return value;
                }
                int main(void) { no_return(); return (int)scalar(1, 2); }
            """.trimIndent())
            val facts = scanInterfaceFixture(artifact, root)
            val projected = DwarfSysvAmd64InterfaceProjection.project(facts, target())
            listOf("scalar", "no_return", "variadic", "pair").forEach { name ->
                val function = projectedFunction(facts, projected, name)
                assertTrue(function.fullyObservable, "$name: ${function.reasons}; return=${function.returnType?.reasons}")
            }
            assertEquals(false, projectedFunction(facts, projected, "scalar").variadic)
            assertEquals(true, projectedFunction(facts, projected, "variadic").variadic)
            assertEquals(DwarfAbiScalarKind.VOID, projectedFunction(facts, projected, "no_return").returnType?.shape?.scalar)
            assertEquals(listOf(DwarfAbiClass.INTEGER, DwarfAbiClass.SSE), projectedFunction(facts, projected, "pair").returnType?.classification?.classes)
            val vector = projectedFunction(facts, projected, "vector")
            assertFalse(vector.fullyObservable)
            assertFalse(vector.returnType?.observable ?: false)
            val global = facts.globals.single { "global_only" in it.sourceName.values }
            val globalRow = projected.globals.single { it["locator"] == JsonPrimitive(global.locator) }
            assertEquals(JsonPrimitive(true), globalRow["observableDeclaredTypeAbi"])
        }

    @Test
    fun `compiled C++ proves qualifier equivalence while retaining raw ambiguity and optimized C preserves ABI facts`() =
        inInterfaceFixtureDirectory { root ->
            val cpp = compile(root, "method.cpp", """
                typedef unsigned long Counter;
                struct Calculator { __attribute__((noinline)) Counter calculate(Counter amount) const; };
                Counter Calculator::calculate(Counter amount) const { return amount + 2; }
                __attribute__((noinline,used)) Counter cpp_scalar(Counter amount) { return amount + 4; }
                int main() { Calculator calculator; return (int)calculator.calculate(3); }
            """.trimIndent(), compiler = "c++")
            val cppFacts = scanInterfaceFixture(cpp, root)
            val cppProjection = DwarfSysvAmd64InterfaceProjection.project(cppFacts, target())
            val scalar = projectedFunction(cppFacts, cppProjection, "cpp_scalar")
            assertTrue(scalar.fullyObservable, scalar.reasons.toString())
            assertEquals(1, scalar.arity)
            val method = projectedFunction(cppFacts, cppProjection, "calculate")
            val rawMethod = cppFacts.functions.single { it.locator == method.locator }
            assertTrue(rawMethod.origins.size > 1)
            // Raw declaration/definition IDs stay ambiguous; only exact qualified-root equality reconciles them.
            assertTrue(method.fullyObservable, method.reasons.toString())
            assertEquals(2, method.arity)
            if (rawMethod.parameterList.state == DwarfInterfaceFactState.AMBIGUOUS) {
                assertTrue(method.evidence.any { it.contains("exact-alias-qualifier-root-equivalence") })
                assertTrue(rawMethod.parameterLists.size > 1)
            }
            assertEquals(DwarfAbiScalarKind.POINTER, method.parameters.first()?.shape?.scalar)
            assertEquals(listOf(DwarfAbiClass.INTEGER), method.returnType?.classification?.classes)
            val optimized = compile(root, "optimized.c", """
                __attribute__((noinline,used)) long optimized(long left, int right) { return left + right; }
                int main(void) { return (int)optimized(1, 2); }
            """.trimIndent(), optimization = "-O2")
            val facts = scanInterfaceFixture(optimized, root)
            val function = projectedFunction(facts, DwarfSysvAmd64InterfaceProjection.project(facts, target()), "optimized")
            assertTrue(function.fullyObservable, "optimized ${function.reasons}; raw=${facts.functions.single { it.locator == function.locator }.toJson()}")
            assertEquals(2, function.arity)
            assertEquals(false, function.variadic)
        }

    private fun project(function: DwarfInterfaceFunctionFacts, vararg types: DwarfInterfaceTypeNode) =
        DwarfSysvAmd64InterfaceProjection.project(listOf(function), types.associateBy { it.id }, target())

    private fun assertUnknownType(type: DwarfInterfaceTypeNode, vararg other: DwarfInterfaceTypeNode) {
        val result = assertNotNull(project(function(returned = known(type.id)), type, *other).functions.single().returnType)
        assertFalse(result.observable, "${type.id} acquired a known ABI: ${result.toJson()}")
        assertTrue(result.reasons.isNotEmpty())
    }

    private fun target() = OracleJson.parse(Files.readAllBytes(Path.of("oracle/targets/sysv-amd64-v1.json"))) as JsonObject

    private fun function(
        returned: DwarfInterfaceFact<String> = known("int"),
        parameters: List<DwarfInterfaceParameterFacts> = emptyList(),
        language: DwarfInterfaceFact<String> = known("29"),
        prototyped: DwarfInterfaceFact<String> = known("1"),
        convention: DwarfInterfaceFact<String> = absent(),
        declaration: DwarfInterfaceFact<String> = absent(),
        sequence: DwarfInterfaceFact<String> = known("function"),
        variadic: DwarfInterfaceFact<Boolean> = DwarfInterfaceFact(DwarfInterfaceFactState.ABSENT,
            evidence = listOf("function"), reasons = listOf("unspecified-parameter-marker-absent")),
        reasons: List<String> = emptyList(),
        lists: List<DwarfInterfaceParameterList>? = null,
    ) = DwarfInterfaceFunctionFacts(
        0x1000UL, 0x401000UL, true, "function", known("fixture"), absent(), language, convention,
        prototyped, absent(), declaration, returned, parameters, sequence,
        lists ?: listOf(DwarfInterfaceParameterList(sequence.values.firstOrNull() ?: "function", parameters, variadic)),
        variadic, (listOf("function") + sequence.values).distinct(), reasons,
    )

    private fun global(id: String, type: String, storage: DwarfInterfaceFact<String> = known("static"),
                       language: DwarfInterfaceFact<String> = known("29")) = DwarfGlobalVariableFacts(
        locator = id, sourceName = known(id), linkageName = absent(), language = language, type = known(type),
        external = absent(), declaration = absent(), artificial = absent(), visibility = absent(),
        byteSize = absent(), alignment = absent(), constant = absent(), scope = known("compilation-unit"),
        location = absent(), address = absent(), rva = absent(), tlsOffset = absent(), storage = storage,
        scopes = emptyList(), origins = listOf(id), reasons = emptyList(),
    )

    private fun parameter(type: String, ordinal: Int = 0) = DwarfInterfaceParameterFacts(
        ordinal, "parameter-$ordinal", absent(), known(type), absent(), listOf("parameter-$ordinal"), emptyList(),
    )

    private fun node(
        id: String, tag: Long,
        name: DwarfInterfaceFact<String> = absent(),
        size: DwarfInterfaceFact<String> = absent(),
        encoding: DwarfInterfaceFact<String> = absent(),
        referenced: DwarfInterfaceFact<String> = absent(),
        attributes: Map<Long, DwarfInterfaceFact<String>> = emptyMap(),
        children: List<DwarfInterfaceTypeChild> = emptyList(),
    ) = DwarfInterfaceTypeNode(id, tag, name, size, encoding, referenced, attributes, children, emptyList())

    private fun aggregate(id: String, bytes: Long, alignment: Long, children: List<DwarfInterfaceTypeChild>,
                          extra: Map<Long, DwarfInterfaceFact<String>> = emptyMap()) =
        node(id, 0x13, size = known(bytes.toString()), attributes = mapOf(0x88L to known(alignment.toString())) + extra, children = children)

    private fun child(id: String, tag: Long, type: String, attributes: Map<Long, DwarfInterfaceFact<String>>) =
        DwarfInterfaceTypeChild(id, tag, absent(), known(type), attributes, emptyList())

    private fun nonInstance(id: String, tag: Long, type: DwarfInterfaceFact<String>,
                            attributes: Map<Long, DwarfInterfaceFact<String>> = emptyMap(),
                            reasons: List<String> = listOf("unsupported-type-child-tag:0x${tag.toString(16)}")) =
        DwarfInterfaceTypeChild(id, tag, known(id), type, attributes, reasons)

    private fun member(id: String, type: String, bytes: Long) = child(id, 0x0d, type, mapOf(0x38L to known(bytes.toString())))

    private fun dimension(id: String, upper: String? = null, count: String? = null) =
        DwarfInterfaceTypeChild(id, 0x21, absent(), absent(), buildMap {
            upper?.let { put(0x2fL, known(it)) }; count?.let { put(0x37L, known(it)) }
        }, emptyList())

    private fun <T> known(value: T) = DwarfInterfaceFact(DwarfInterfaceFactState.KNOWN, listOf(value), listOf("fixture-evidence"))
    private fun <T> absent() = DwarfInterfaceFact<T>(DwarfInterfaceFactState.ABSENT)
    private fun <T> unknown(reason: String = "unresolved-fixture-fact") =
        DwarfInterfaceFact<T>(DwarfInterfaceFactState.UNKNOWN, reasons = listOf(reason))
    private fun <T> ambiguous(vararg values: T) =
        DwarfInterfaceFact(DwarfInterfaceFactState.AMBIGUOUS, values.toList(), reasons = listOf("conflicting-fixture-facts"))

    private val intType = node("int", 0x24, size = known("4"), encoding = known("5"))
    private val floatType = node("float", 0x24, size = known("4"), encoding = known("4"))
    private val doubleType = node("double", 0x24, size = known("8"), encoding = known("4"))

    private fun projectedFunction(facts: BoundedDwarfInterfaceFacts, projected: DwarfSysvAmd64Projection, name: String): DwarfProjectedFunction {
        val raw = facts.functions.single { name in it.sourceName.values }
        return projected.functions.single { it.locator == raw.locator }
    }

    private fun compile(root: Path, name: String, source: String, compiler: String = "cc", optimization: String = "-O0"): Path {
        val sourcePath = root.resolve(name)
        val artifact = root.resolve("${name.substringBeforeLast('.')}.elf")
        val diagnostics = root.resolve("${name.substringBeforeLast('.')}.log")
        Files.writeString(sourcePath, source)
        val dialect = if (name.endsWith(".cpp")) "-std=c++14" else "-std=c11"
        val process = ProcessBuilder(compiler, dialect, optimization, "-g", "-gdwarf-5", "-fno-eliminate-unused-debug-types",
            "-fno-pie", "-no-pie", sourcePath.toString(), "-o", artifact.toString())
            .directory(root.toFile()).redirectErrorStream(true).redirectOutput(diagnostics.toFile()).apply {
                environment()["TMPDIR"] = root.toString(); environment()["TMP"] = root.toString(); environment()["TEMP"] = root.toString()
            }.start()
        try {
            assertTrue(process.waitFor(30, TimeUnit.SECONDS), "fixture compiler exceeded bounded runtime")
            assertEquals(0, process.exitValue(), Files.readString(diagnostics).take(16_384))
        } finally {
            if (process.isAlive) process.destroyForcibly().waitFor(5, TimeUnit.SECONDS)
        }
        return artifact
    }
}
