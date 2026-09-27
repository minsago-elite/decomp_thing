package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleJson
import decompengine.oracle.structural.DwarfAbiScalarKind
import decompengine.oracle.structural.DwarfSysvAmd64InterfaceProjection
import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.nio.file.Path
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class BoundedDwarfInterfaceTypesTest {
    @Test
    fun `ABI layout scope retains terminal pointer references without expanding unrelated pointees`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val tags = listOf(0x0fL, 0x10L, 0x42L)
            val entries = tags.indices.map { emitted("entry$it", "pointer$it", it) }
            val pointers = tags.mapIndexed { index, tag ->
                die("pointer$index", tag, listOf(number(0x0b, 8), reference(0x49, "tail0")))
            }
            val tail = (0 until 20).map { die("tail$it", 0x16,
                listOf(reference(0x49, if (it == 19) "int" else "tail${it + 1}"))) } + integerType()
            val fixture = typeElf(*(entries + pointers + tail).toTypedArray())
            val limits = BoundedDwarfInterfaceFactLimits(maximumTypeDepth = 1, maximumTypes = 3,
                typeGraphScope = BoundedDwarfTypeGraphScope.ABI_LAYOUT)
            val facts = scan(root, fixture, limits)
            assertEquals(3, facts.types.size)
            assertEquals(JsonPrimitive("abi-layout"), facts.limits.toJson()["typeGraphScope"])
            facts.types.values.forEach { node ->
                known(node.type, fixture.locator("tail0"))
                assertEquals(listOf("${node.id}:attribute=0x49"), node.type.evidence)
                assertTrue("type-reference-not-expanded:abi-layout-pointee" in node.type.reasons)
            }
            val projection = DwarfSysvAmd64InterfaceProjection.project(facts, target())
            assertTrue(projection.functions.all { it.returnType?.observable == true })
            assertTrue(projection.functions.all { it.returnType?.shape?.scalar == DwarfAbiScalarKind.POINTER })
            assertFalse(fixture.locator("tail0") in facts.types)
            assertEquals(BoundedDwarfTypeGraphScope.FULL_REFERENCES, BoundedDwarfInterfaceFactLimits().typeGraphScope)
            assertFailsWith<FullTreeControlException> {
                scan(root, fixture, limits.copy(typeGraphScope = BoundedDwarfTypeGraphScope.FULL_REFERENCES))
            }
        }

    @Test
    fun `ABI layout keeps every nonlayout child fact while expanding actual aggregate members`(): Unit =
        inInterfaceFixtureDirectory { root ->
            fun fixture(unknownChild: Boolean): TypeGraphElf {
                val children = listOf(die("field", 0x0d, listOf(reference(0x49, "int"), number(0x38, 0)))) +
                    listOf(0x2eL, 0x2fL, 0x13L).mapIndexed { index, tag -> die("metadata$index", tag,
                        listOf(reference(0x49, "tail0"), reference(0x1d, "tail0"))) } +
                    if (unknownChild) listOf(die("unknown", 0x777, listOf(reference(0x49, "int")))) else emptyList()
                val tail = (0 until 20).map { die("tail$it", 0x16,
                    listOf(reference(0x49, if (it == 19) "int" else "tail${it + 1}"))) }
                return typeElf(*(listOf(emitted("entry", "record"), die("record", 0x13,
                    listOf(number(0x0b, 4), number(0x88, 4)), children), integerType()) + tail).toTypedArray())
            }
            val limits = BoundedDwarfInterfaceFactLimits(maximumTypeDepth = 2,
                typeGraphScope = BoundedDwarfTypeGraphScope.ABI_LAYOUT)
            val input = fixture(false)
            val facts = scan(root, input, limits)
            assertEquals(setOf(input.locator("record"), input.locator("int")), facts.types.keys)
            val children = facts.types.getValue(input.locator("record")).children
            assertEquals(listOf("field", "metadata0", "metadata1", "metadata2").map(input::locator), children.map { it.id })
            assertTrue(children.first().type.reasons.isEmpty())
            children.drop(1).forEach { child ->
                listOf(0x49L, 0x1dL).forEach { attribute ->
                    val reference = child.attributes.getValue(attribute)
                    known(reference, input.locator("tail0"))
                    assertTrue("type-reference-not-expanded:abi-layout-non-layout-child" in reference.reasons)
                    assertEquals(listOf("${child.id}:attribute=0x${attribute.toString(16)}"), reference.evidence)
                }
            }
            val projected = DwarfSysvAmd64InterfaceProjection.project(facts, target()).functions.single().returnType
            assertEquals(true, projected?.observable)
            assertEquals(1, projected?.shape?.fields?.size)
            val missingMember = DwarfSysvAmd64InterfaceProjection.project(facts.functions,
                facts.types - input.locator("int"), target()).functions.single().returnType
            assertEquals(false, missingMember?.observable)
            val unsupported = DwarfSysvAmd64InterfaceProjection.project(scan(root, fixture(true), limits), target())
            assertEquals(false, unsupported.functions.single().returnType?.observable)
            assertFailsWith<FullTreeControlException> {
                scan(root, input, limits.copy(typeGraphScope = BoundedDwarfTypeGraphScope.FULL_REFERENCES))
            }
        }

    @Test
    fun `deferred pointee expands independently for function and global by value roots in either order`(): Unit =
        inInterfaceFixtureDirectory { root ->
            for (global in listOf(false, true)) for (pointerFirst in listOf(false, true)) {
                val pointerEntry = emitted("pointerEntry", "pointer")
                val valueEntry = if (global) die("valueEntry", 0x34, listOf(reference(0x49, "record")))
                    else emitted("valueEntry", "record", 1)
                val entries = if (pointerFirst) listOf(pointerEntry, valueEntry) else listOf(valueEntry, pointerEntry)
                val fixture = typeElf(*(entries + listOf(
                    die("pointer", 0x0f, listOf(number(0x0b, 8), reference(0x49, "record"))),
                    die("record", 0x13, listOf(number(0x0b, 4), number(0x88, 4)), listOf(
                        die("field", 0x0d, listOf(reference(0x49, "int"), number(0x38, 0))),
                    )), integerType(),
                )).toTypedArray())
                val facts = scan(root, fixture, BoundedDwarfInterfaceFactLimits(maximumTypeDepth = 2,
                    typeGraphScope = BoundedDwarfTypeGraphScope.ABI_LAYOUT))
                assertEquals(3, facts.types.size)
                val deferred = facts.types.getValue(fixture.locator("pointer")).type
                known(deferred, fixture.locator("record"))
                assertTrue("type-reference-not-expanded:abi-layout-pointee" in deferred.reasons)
                val projection = DwarfSysvAmd64InterfaceProjection.project(facts, target())
                val record = projection.types.single { it.rawTypeId == fixture.locator("record") }
                assertTrue(record.observable, record.reasons.toString())
                assertEquals(1, record.shape?.fields?.size)
                assertEquals(DwarfAbiScalarKind.INTEGER, record.shape?.fields?.single()?.type?.scalar)
            }
        }

    @Test
    fun `ABI layout expands aliases enums arrays bases and subroutine formal parameter types`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val fixture = typeElf(
                emitted("entry", "subroutine"),
                die("subroutine", 0x15, listOf(reference(0x49, "alias")), listOf(
                    die("parameter", 0x05, listOf(reference(0x49, "derived"))),
                )),
                die("derived", 0x13, children = listOf(
                    die("base", 0x1c, listOf(reference(0x49, "baseType"))),
                    die("field", 0x0d, listOf(reference(0x49, "array"))),
                )),
                die("baseType", 0x13, children = listOf(die("baseField", 0x0d, listOf(reference(0x49, "int"))))),
                die("array", 0x01, listOf(reference(0x49, "enum")), listOf(
                    die("dimension", 0x21, listOf(reference(0x49, "int"), number(0x37, 2))),
                )),
                die("enum", 0x04, listOf(reference(0x49, "alias"))),
                die("alias", 0x16, listOf(reference(0x49, "const"))),
                die("const", 0x26, listOf(reference(0x49, "int"))), integerType(),
            )
            val full = scan(root, fixture)
            val layout = scan(root, fixture, BoundedDwarfInterfaceFactLimits(typeGraphScope = BoundedDwarfTypeGraphScope.ABI_LAYOUT))
            assertEquals(8, layout.types.size)
            assertEquals(full.types.mapValues { it.value.toJson() }, layout.types.mapValues { it.value.toJson() })
        }

    @Test
    fun `deferred references still reject nonboundary targets and retain unsupported target tags`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val limits = BoundedDwarfInterfaceFactLimits(typeGraphScope = BoundedDwarfTypeGraphScope.ABI_LAYOUT)
            val pointer = typeElf(emitted("entry", "pointer"),
                die("pointer", 0x0f, listOf(reference(0x49, "int", addend = 1))), integerType())
            val method = typeElf(emitted("entry", "record"), die("record", 0x13, children = listOf(
                die("method", 0x2e, listOf(reference(0x49, "int", addend = 1))),
            )), integerType())
            listOf(pointer, method).forEach { assertFailsWith<FullTreeControlException> { scan(root, it, limits) } }
            val unsupported = typeElf(emitted("entry", "pointer"),
                die("pointer", 0x0f, listOf(reference(0x49, "declaration"))), die("declaration", 0x2e))
            val facts = scan(root, unsupported, limits)
            val reference = facts.types.getValue(unsupported.locator("pointer")).type
            assertEquals(DwarfInterfaceFactState.UNKNOWN, reference.state)
            assertEquals(listOf(unsupported.locator("declaration")), reference.values)
            assertTrue("unsupported-type-tag:0x2e" in reference.reasons)
            assertTrue("type-reference-not-expanded:abi-layout-pointee" in reference.reasons)
            assertEquals(1, facts.types.size)
        }

    @Test
    fun `unsupported function attributes preserve each physical and inherited occurrence`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val staticLink = raw(0x48, FULL_TREE_DW_FORM_EXPRLOC,
                uleb(2) + byteArrayOf(0x91.toByte(), 0x78))
            val fixture = typeElf(
                die("declaration", 0x2e, listOf(text(0x03, "unsupported_function"), staticLink,
                    raw(0x69, FULL_TREE_DW_FORM_REF_SIG8, fixed(0x1122, 8)))),
                die("definition", 0x2e, listOf(address(0x11, 0x400100),
                    reference(0x47, "declaration"), staticLink, address(0x56, 0x400180))),
            )
            val function = scan(root, fixture).functions.single()
            assertEquals(fixture.locator("definition"), function.locator)
            known(function.sourceName, "unsupported_function")
            val reasons = function.reasons.filter { it.startsWith("unsupported-function-attribute:") }
            val expected = setOf(
                "unsupported-function-attribute:0x48:form=0x18:${fixture.locator("definition")}",
                "unsupported-function-attribute:0x56:form=0x1:${fixture.locator("definition")}",
                "unsupported-function-attribute:0x48:form=0x18:${fixture.locator("declaration")}",
                "unsupported-function-attribute:0x69:form=0x20:${fixture.locator("declaration")}",
            )
            assertEquals(expected.size, reasons.size)
            assertEquals(expected, reasons.toSet())
        }

    @Test
    fun `recursive structure keeps member pointer and back edge with deterministic evidence`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val fixture = typeElf(
                emitted("entry", "node"),
                die("node", 0x13, listOf(text(0x03, "Node"), number(0x0b, 16)), listOf(
                    die("next", 0x0d, listOf(text(0x03, "next"), reference(0x49, "pointer"), number(0x38, 8))),
                )),
                die("pointer", 0x0f, listOf(number(0x0b, 8), reference(0x49, "node"))),
            )
            val facts = scan(root, fixture)
            val node = facts.types.getValue(fixture.locator("node"))
            val pointer = facts.types.getValue(fixture.locator("pointer"))
            assertEquals(2, facts.types.size)
            known(facts.functions.single().returnType, fixture.locator("node"))
            known(node.byteSize, "16")
            known(node.children.single().type, pointer.id)
            known(node.children.single().attributes.getValue(0x38), "8")
            known(pointer.type, node.id)
            assertTrue(pointer.type.reasons.contains("type-reference-cycle:${node.id}"))
            assertContentEquals(facts.canonicalBytes(), scan(root, fixture).canonicalBytes())
        }

    @Test
    fun `typedef qualifier base and ordered array bounds retain raw attributes`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val fixture = typeElf(
                emitted("entry", "array"),
                die("array", 0x01, listOf(reference(0x49, "alias")), listOf(
                    die("outer", 0x21, listOf(number(0x22, 0), number(0x2f, 3))),
                    die("inner", 0x21, listOf(number(0x22, 2), number(0x2f, 6))),
                )),
                die("alias", 0x16, listOf(text(0x03, "Element"), reference(0x49, "const"))),
                die("const", 0x26, listOf(reference(0x49, "int"))),
                integerType(),
            )
            val facts = scan(root, fixture)
            val array = facts.types.getValue(fixture.locator("array"))
            val alias = facts.types.getValue(fixture.locator("alias"))
            val qualifier = facts.types.getValue(fixture.locator("const"))
            val base = facts.types.getValue(fixture.locator("int"))
            assertEquals(listOf(fixture.locator("outer"), fixture.locator("inner")), array.children.map { it.id })
            assertEquals(listOf("3", "6"), array.children.map { it.attributes.getValue(0x2f).values.single() })
            assertEquals(listOf("0", "2"), array.children.map { it.attributes.getValue(0x22).values.single() })
            known(array.type, alias.id)
            known(alias.name, "Element")
            known(alias.type, qualifier.id)
            known(qualifier.type, base.id)
            assertEquals(DwarfInterfaceFactState.ABSENT, qualifier.name.state)
            assertEquals(DwarfInterfaceFactState.ABSENT, qualifier.byteSize.state)
            known(base.name, "int")
            known(base.byteSize, "4")
            known(base.encoding, "5")
        }

    @Test
    fun `all direct children survive including unsupported nested child semantics`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val fixture = typeElf(
                emitted("entry", "structure"),
                die("structure", 0x13, children = listOf(
                    die("first", 0x0d, listOf(text(0x03, "first"), reference(0x49, "int"))),
                    die("method", 0x2e, listOf(text(0x03, "method")), listOf(
                        die("hiddenParameter", 0x05, listOf(reference(0x49, "int"))),
                    )),
                    die("last", 0x0d, listOf(text(0x03, "last"), reference(0x49, "int"))),
                )),
                integerType(),
            )
            val children = scan(root, fixture).types.getValue(fixture.locator("structure")).children
            assertEquals(listOf("first", "method", "last"), children.map { it.name.values.single() })
            assertEquals(listOf(0x0dL, 0x2eL, 0x0dL), children.map { it.tag })
            assertTrue("unsupported-type-child-tag:0x2e" in children[1].reasons)
            assertTrue("nested-type-child-children-unrepresented:${fixture.locator("method")}" in children[1].reasons)
            assertFalse(children.any { it.id == fixture.locator("hiddenParameter") })
        }

    @Test
    fun `completing structure inherits its name but not declaration flag`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val fixture = typeElf(
                emitted("entry", "definition"),
                die("declaration", 0x13, listOf(text(0x03, "Forward"), flag(0x3c))),
                die("definition", 0x13, listOf(reference(0x47, "declaration"), number(0x0b, 4)), listOf(
                    die("field", 0x0d, listOf(reference(0x49, "int"))),
                )),
                integerType(),
            )
            val definition = scan(root, fixture).types.getValue(fixture.locator("definition"))
            known(definition.name, "Forward")
            assertTrue(definition.name.evidence.any { it.startsWith(fixture.locator("declaration")) })
            assertTrue(definition.attributes[0x3c]?.state in listOf(null, DwarfInterfaceFactState.ABSENT))
            known(definition.byteSize, "4")
        }

    @Test
    fun `nearest inherited override wins while independent conflicting branches stay ambiguous`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val fixture = typeElf(
                emitted("inheritedEntry", "leaf", 0),
                emitted("conflictEntry", "conflict", 1),
                emitted("ownEntry", "own", 2),
                die("old", 0x16, listOf(text(0x03, "Old"), reference(0x49, "int"))),
                die("middle", 0x16, listOf(text(0x03, "Middle"), reference(0x47, "old"))),
                die("leaf", 0x16, listOf(reference(0x47, "middle"))),
                die("right", 0x16, listOf(text(0x03, "Right"), reference(0x49, "float"))),
                die("conflict", 0x16, listOf(reference(0x47, "middle"), reference(0x31, "right"))),
                die("own", 0x16, listOf(text(0x03, "Own"), reference(0x49, "int"),
                    reference(0x47, "middle"), reference(0x31, "right"))),
                integerType(),
                die("float", 0x24, listOf(text(0x03, "float"), number(0x0b, 4), number(0x3e, 4))),
            )
            val types = scan(root, fixture).types
            known(types.getValue(fixture.locator("leaf")).name, "Middle")
            val conflict = types.getValue(fixture.locator("conflict"))
            assertEquals(DwarfInterfaceFactState.AMBIGUOUS, conflict.name.state)
            assertEquals(setOf("Middle", "Right"), conflict.name.values.toSet())
            assertEquals(DwarfInterfaceFactState.AMBIGUOUS, conflict.type.state)
            assertEquals(setOf(fixture.locator("int"), fixture.locator("float")), conflict.type.values.toSet())
            known(types.getValue(fixture.locator("own")).name, "Own")
            known(types.getValue(fixture.locator("own")).type, fixture.locator("int"))
        }

    @Test
    fun `absent type remains distinct from unsupported supplementary references`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val fixture = typeElf(
                emitted("absentEntry", null, 0),
                emitted("pointerEntry", "pointer", 1),
                die("supplementaryEntry", 0x2e, listOf(text(0x03, "supplementaryEntry"),
                    address(0x11, 0x400110), raw(0x49, FULL_TREE_DW_FORM_REF_SUP4, fixed(7, 4)))),
                die("pointer", 0x0f, listOf(number(0x0b, 8))),
                version = 5,
            )
            val facts = scan(root, fixture)
            assertEquals(DwarfInterfaceFactState.ABSENT, facts.functions[0].returnType.state)
            assertEquals(DwarfInterfaceFactState.ABSENT, facts.types.getValue(fixture.locator("pointer")).type.state)
            val supplementary = facts.functions[2].returnType
            assertEquals(DwarfInterfaceFactState.UNKNOWN, supplementary.state)
            assertTrue(supplementary.values.isEmpty())
            assertTrue(supplementary.reasons.any { it.startsWith("unsupported-type-reference-form:") })
        }

    @Test
    fun `unavailable supplementary specification makes inherited type facts unknown`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val fixture = typeElf(
                emitted("entry", "alias"),
                die("alias", 0x16, listOf(raw(0x47, FULL_TREE_DW_FORM_REF_SUP4, fixed(7, 4)))),
                version = 5,
            )
            val alias = scan(root, fixture).types.getValue(fixture.locator("alias"))
            for (fact in listOf(alias.name, alias.type, alias.byteSize, alias.encoding)) {
                assertEquals(DwarfInterfaceFactState.UNKNOWN, fact.state)
                assertTrue("unsupported-origin-specification-reference:0x47" in fact.reasons)
            }
        }

    @Test
    fun `reference into an attribute operand is malformed rather than unknown`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val fixture = typeElf(
                die("entry", 0x2e, listOf(text(0x03, "entry"), address(0x11, 0x400100),
                    reference(0x49, "int", addend = 1))),
                integerType(),
            )
            assertFailsWith<FullTreeControlException> { scan(root, fixture) }
        }

    @Test
    fun `member location list offsets never become known constant layouts`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val modern = typeElf(
                emitted("entry", "structure"),
                die("structure", 0x13, children = listOf(
                    die("direct", 0x0d, listOf(raw(0x38, FULL_TREE_DW_FORM_SEC_OFFSET, fixed(8, 4)))),
                    die("indirect", 0x0d, listOf(raw(0x38, FULL_TREE_DW_FORM_INDIRECT,
                        uleb(FULL_TREE_DW_FORM_SEC_OFFSET) + fixed(8, 4)))),
                    die("constant", 0x0d, listOf(number(0x38, 8))),
                )),
            )
            val children = scan(root, modern).types.getValue(modern.locator("structure")).children
            for (child in children.take(2)) {
                val location = child.attributes.getValue(0x38)
                assertEquals(DwarfInterfaceFactState.UNKNOWN, location.state)
                assertTrue(location.values.isEmpty())
            }
            known(children.last().attributes.getValue(0x38), "8")

            val legacy = typeElf(
                emitted("entry", "structure"),
                die("structure", 0x13, children = listOf(
                    die("offset", 0x0d, listOf(raw(0x38, FULL_TREE_DW_FORM_DATA4, fixed(8, 4)))),
                    die("constant", 0x0d, listOf(number(0x38, 8))),
                )),
                version = 3,
            )
            val legacyChildren = scan(root, legacy).types.getValue(legacy.locator("structure")).children
            assertEquals(DwarfInterfaceFactState.UNKNOWN, legacyChildren.first().attributes.getValue(0x38).state)
            known(legacyChildren.last().attributes.getValue(0x38), "8")
        }

    @Test
    fun `anonymous names are valid empty facts and unsupported target tags remain unknown`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val fixture = typeElf(
                emitted("anonymousEntry", "anonymous", 0),
                emitted("unsupportedEntry", "variable", 1),
                die("anonymous", 0x13, listOf(text(0x03, ""))),
                die("variable", 0x34, listOf(text(0x03, "notAType"))),
            )
            val facts = scan(root, fixture)
            known(facts.types.getValue(fixture.locator("anonymous")).name, "")
            assertEquals(DwarfInterfaceFactState.UNKNOWN, facts.functions[1].returnType.state)
            assertEquals(listOf(fixture.locator("variable")), facts.functions[1].returnType.values)
            assertTrue("unsupported-type-tag:0x34" in facts.functions[1].returnType.reasons)
        }

    @Test
    fun `calling convention and prototype flags reject direct and indirect section offsets`(): Unit =
        inInterfaceFixtureDirectory { root ->
            fun offset(name: Long, indirect: Boolean) = if (indirect) {
                raw(name, FULL_TREE_DW_FORM_INDIRECT, uleb(FULL_TREE_DW_FORM_SEC_OFFSET) + fixed(1, 4))
            } else raw(name, FULL_TREE_DW_FORM_SEC_OFFSET, fixed(1, 4))
            val fixture = typeElf(
                die("direct", 0x2e, listOf(text(0x03, "direct"), address(0x11, 0x400100),
                    offset(0x36, false), offset(0x27, false))),
                die("indirect", 0x2e, listOf(text(0x03, "indirect"), address(0x11, 0x400108),
                    offset(0x36, true), offset(0x27, true))),
            )
            for (function in scan(root, fixture).functions) {
                for (fact in listOf(function.callingConvention, function.prototyped)) {
                    assertEquals(DwarfInterfaceFactState.UNKNOWN, fact.state)
                    assertTrue(fact.values.isEmpty())
                    assertTrue("unsupported-integral-form" in fact.reasons)
                }
            }
        }

    @Test
    fun `variadic marker before a formal parameter preserves order and ambiguity`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val fixture = typeElf(
                die("entry", 0x2e, listOf(text(0x03, "entry"), address(0x11, 0x400100)), listOf(
                    die("ellipsis", 0x18),
                    die("parameter", 0x05, listOf(text(0x03, "value"), reference(0x49, "int"))),
                )),
                integerType(),
            )
            val function = scan(root, fixture).functions.single()
            assertEquals(DwarfInterfaceFactState.AMBIGUOUS, function.variadic.state)
            assertEquals(DwarfInterfaceFactState.AMBIGUOUS, function.parameterList.state)
            assertTrue("unspecified-parameter-marker-is-not-last" in function.variadic.reasons)
            assertTrue("unspecified-parameter-marker-is-not-last" in function.parameterList.reasons)
            assertEquals(listOf(fixture.locator("ellipsis"), fixture.locator("parameter")),
                function.parameterLists.single().childOrder)
            assertEquals(listOf(fixture.locator("parameter")), function.parameters.map { it.locator })
            known(function.parameters.single().type, fixture.locator("int"))
            assertFailsWith<UnsupportedOperationException> {
                (function.parameterLists.single().childOrder as MutableList<String>).clear()
            }
        }

    @Test
    fun `converging inheritance charges retained type facts and still bounds distinct output`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val longName = "T".repeat(4096)
            val branches = (0 until 15).map { index ->
                fun target(child: Int) = if (child < 15) "branch$child" else "leaf"
                die("branch$index", 0x24, listOf(
                    reference(0x31, target(index * 2 + 1)),
                    reference(0x47, target(index * 2 + 2)),
                ))
            }
            val fixture = typeElf(*(listOf(emitted("entry", "branch0")) + branches +
                die("leaf", 0x24, listOf(text(0x03, longName), number(0x0b, 4), number(0x3e, 5))))
                .toTypedArray())
            val generous = scan(root, fixture)
            val bounded = scan(root, fixture, BoundedDwarfInterfaceFactLimits(maximumOutputBytes = 128 * 1024))
            assertEquals(generous.functions.map { it.toJson() }, bounded.functions.map { it.toJson() })
            assertEquals(generous.types.mapValues { it.value.toJson() }, bounded.types.mapValues { it.value.toJson() })
            val retained = bounded.types.getValue(fixture.locator("branch0"))
            known(retained.name, longName)
            assertEquals(listOf("${fixture.locator("leaf")}:attribute=0x3"), retained.name.evidence)
            known(retained.attributes.getValue(0x31), fixture.locator("branch1"))
            known(retained.attributes.getValue(0x47), fixture.locator("branch2"))

            val distinct = typeElf(*(0 until 16).flatMap { index -> listOf(
                emitted("entry$index", "type$index", index),
                die("type$index", 0x24, listOf(text(0x03, "$index$longName".take(4096)),
                    number(0x0b, 4), number(0x3e, 5))),
            ) }.toTypedArray())
            val failure = assertFailsWith<FullTreeControlException> {
                scan(root, distinct, BoundedDwarfInterfaceFactLimits(maximumOutputBytes = 128 * 1024))
            }
            assertTrue(failure.message.orEmpty().contains("retained fact bound"), failure.message)
        }

    @Test
    fun `type count depth direct children and output budgets fail closed`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val fixture = typeElf(
                emitted("entry", "structure"),
                die("structure", 0x13, children = listOf(
                    die("first", 0x0d, listOf(reference(0x49, "int"))),
                    die("second", 0x0d, listOf(reference(0x49, "int"))),
                )),
                integerType(),
            )
            assertEquals(2, scan(root, fixture, BoundedDwarfInterfaceFactLimits(
                maximumTypes = 2, maximumTypeDepth = 2, maximumChildrenPerType = 2,
            )).types.size)
            for ((limits, message) in listOf(
                BoundedDwarfInterfaceFactLimits(maximumTypes = 1) to "type-count bound",
                BoundedDwarfInterfaceFactLimits(maximumTypeDepth = 1) to "depth bound",
                BoundedDwarfInterfaceFactLimits(maximumChildrenPerType = 1) to "child-count bound",
                BoundedDwarfInterfaceFactLimits(maximumOutputBytes = 1000) to "retained fact bound",
                BoundedDwarfInterfaceFactLimits(maximumTypeTraversalSteps = 1) to "traversal-work bound",
            )) {
                val failure = assertFailsWith<FullTreeControlException> { scan(root, fixture, limits) }
                assertTrue(failure.message.orEmpty().contains(message), failure.message)
            }
        }

    @Test
    fun `cached suffixes cannot bypass the depth ceiling when chain is resolved backwards`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val functions = (0..4).map { index -> emitted("entry$index", "type$index", index) }
            val types = listOf(integerType("type0")) + (1..4).map { index ->
                die("type$index", 0x16, listOf(reference(0x49, "type${index - 1}")))
            }
            val fixture = typeElf(*(functions + types).toTypedArray())
            assertEquals(5, scan(root, fixture, BoundedDwarfInterfaceFactLimits(maximumTypeDepth = 5)).types.size)
            val failure = assertFailsWith<FullTreeControlException> {
                scan(root, fixture, BoundedDwarfInterfaceFactLimits(maximumTypeDepth = 4))
            }
            assertTrue(failure.message.orEmpty().contains("depth bound"))
        }

    @Test
    fun `names matching graph locators do not create synthetic type edges`(): Unit =
        inInterfaceFixtureDirectory { root ->
            fun fixture(name: String) = typeElf(
                emitted("deepEntry", "outer", 0),
                emitted("namedEntry", "named", 1),
                die("outer", 0x16, listOf(reference(0x49, "inner"))),
                die("inner", 0x16, listOf(reference(0x49, "int"))),
                integerType(),
                die("named", 0x24, listOf(text(0x03, name))),
            )
            val locator = fixture("placeholder").locator("outer")
            val actual = fixture(locator)
            assertEquals(locator, actual.locator("outer"))
            val facts = scan(root, actual, BoundedDwarfInterfaceFactLimits(maximumTypeDepth = 3))
            known(facts.types.getValue(actual.locator("named")).name, locator)
        }

    @Test
    fun `dense cyclic component accepts within the traversal budget without enumerating paths`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val count = 9
            val types = (0 until count).map { owner ->
                die("type$owner", 0x13, children = (0 until count).map { target ->
                    die("member${owner}To$target", 0x0d, listOf(reference(0x49, "type$target")))
                })
            }
            val fixture = typeElf(*(listOf(emitted("entry", "type0")) + types).toTypedArray())
            val limits = BoundedDwarfInterfaceFactLimits(maximumTypeDepth = count,
                maximumTypeTraversalSteps = 256)
            val facts = scan(root, fixture, limits)
            assertEquals(count, facts.types.size)
            assertEquals(count * count, facts.types.values.sumOf { it.children.size })
            val failure = assertFailsWith<FullTreeControlException> {
                scan(root, fixture, limits.copy(maximumTypeTraversalSteps = 64))
            }
            assertTrue(failure.message.orEmpty().contains("traversal-work bound"), failure.message)
        }

    @Test
    fun `large component bound falls back to the actual short simple paths from every root`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val leaves = 6
            val entries = listOf(emitted("hubEntry", "hub")) +
                (0 until leaves).map { emitted("leafEntry$it", "leaf$it", it + 1) }
            val types = listOf(die("hub", 0x13, children = (0 until leaves).map {
                die("hubMember$it", 0x0d, listOf(reference(0x49, "leaf$it")))
            })) + (0 until leaves).map { die("leaf$it", 0x0f, listOf(reference(0x49, "hub"))) }
            val fixture = typeElf(*(entries + types).toTypedArray())
            val limits = BoundedDwarfInterfaceFactLimits(maximumTypeDepth = 3,
                maximumTypeTraversalSteps = 256)
            assertEquals(leaves + 1, scan(root, fixture, limits).types.size)
            val failure = assertFailsWith<FullTreeControlException> {
                scan(root, fixture, limits.copy(maximumTypeDepth = 2))
            }
            assertTrue(failure.message.orEmpty().contains("depth bound"), failure.message)
        }

    @Test
    fun `component successor bounds preserve depth checks when a suffix was discovered first`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val fixture = typeElf(
                emitted("suffixEntry", "c"), emitted("incomingEntry", "a", 1),
                die("a", 0x0f, listOf(reference(0x49, "b"))),
                die("b", 0x13, children = listOf(
                    die("backToA", 0x0d, listOf(reference(0x49, "a"))),
                    die("forwardToC", 0x0d, listOf(reference(0x49, "c"))),
                )),
                die("c", 0x0f, listOf(reference(0x49, "d"))),
                die("d", 0x13, children = listOf(
                    die("backToC", 0x0d, listOf(reference(0x49, "c"))),
                    die("forwardToE", 0x0d, listOf(reference(0x49, "e"))),
                )),
                integerType("e"),
            )
            assertEquals(5, scan(root, fixture, BoundedDwarfInterfaceFactLimits(maximumTypeDepth = 5)).types.size)
            val failure = assertFailsWith<FullTreeControlException> {
                scan(root, fixture, BoundedDwarfInterfaceFactLimits(maximumTypeDepth = 4))
            }
            assertTrue(failure.message.orEmpty().contains("depth bound"), failure.message)
        }

    @Test
    fun `shared cyclic tails fit the traversal bound without weakening incoming depth checks`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val layers = 10
            val branches = (0 until layers).flatMap { layer ->
                listOf("left", "right").map { side ->
                    die("$side$layer", 0x13, children = listOf("left", "right").map { target ->
                        val next = if (layer + 1 == layers) "${target}Cycle" else "$target${layer + 1}"
                        die("$side${layer}To$target", 0x0d, listOf(reference(0x49, next)))
                    })
                }
            }
            val fixture = typeElf(*(listOf(emitted("leftEntry", "left0"), emitted("rightEntry", "right0", 1)) +
                branches + listOf(
                    die("leftCycle", 0x0f, listOf(reference(0x49, "rightCycle"))),
                    die("rightCycle", 0x0f, listOf(reference(0x49, "leftCycle"))),
                )).toTypedArray())
            val limits = BoundedDwarfInterfaceFactLimits(maximumTypeDepth = layers + 2,
                maximumTypeTraversalSteps = 256)
            val bounded = scan(root, fixture, limits)
            assertEquals(layers * 2 + 2, bounded.types.size)
            assertEquals(scan(root, fixture).types.mapValues { it.value.toJson() },
                bounded.types.mapValues { it.value.toJson() })
            val failure = assertFailsWith<FullTreeControlException> {
                scan(root, fixture, limits.copy(maximumTypeDepth = layers + 1))
            }
            assertTrue(failure.message.orEmpty().contains("depth bound"), failure.message)
        }

    @Test
    fun `cyclic upper bounds that do not fit are rechecked instead of rejecting a shorter path`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val types = listOf(die("hub", 0x13, children = (0 until 3).map {
                die("hubMember$it", 0x0d, listOf(reference(0x49, "leaf$it")))
            })) + (0 until 3).map { die("leaf$it", 0x0f, listOf(reference(0x49, "hub"))) }
            val fixture = typeElf(*(listOf(emitted("firstEntry", "leaf0"), emitted("secondEntry", "leaf1", 1)) +
                types).toTypedArray())
            // The four-node SCC bound cannot prove a depth of three. The first root's
            // cyclic bound also cannot prove its suffix fits beneath the second root.
            assertEquals(4, scan(root, fixture, BoundedDwarfInterfaceFactLimits(maximumTypeDepth = 3)).types.size)
        }

    @Test
    fun `a cyclic tail cut by an external ancestor cannot become a global upper bound`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val fixture = typeElf(
                emitted("firstEntry", "root"), emitted("secondEntry", "cycle", 1),
                die("root", 0x13, children = listOf(
                    die("cycleMember", 0x0d, listOf(reference(0x49, "cycle"))),
                    die("leafMember", 0x0d, listOf(reference(0x49, "leaf"))),
                )),
                die("cycle", 0x0f, listOf(reference(0x49, "root"))),
                integerType("leaf"),
            )
            val failure = assertFailsWith<FullTreeControlException> {
                scan(root, fixture, BoundedDwarfInterfaceFactLimits(maximumTypeDepth = 2))
            }
            assertTrue(failure.message.orEmpty().contains("depth bound"), failure.message)
            assertEquals(3, scan(root, fixture, BoundedDwarfInterfaceFactLimits(maximumTypeDepth = 3)).types.size)
        }

    @Test
    fun `cycle suffix depth is rechecked from a later incoming root`(): Unit =
        inInterfaceFixtureDirectory { root ->
            fun fixture(withIncomingRoot: Boolean): TypeGraphElf {
                val functions = listOf(emitted("cycleEntry", "a")) +
                    if (withIncomingRoot) listOf(emitted("incomingEntry", "c", 1)) else emptyList()
                val types = listOf(
                    die("a", 0x0f, listOf(reference(0x49, "b"))),
                    die("b", 0x0f, listOf(reference(0x49, "a"))),
                    die("c", 0x0f, listOf(reference(0x49, "b"))),
                )
                return typeElf(*(functions + types).toTypedArray())
            }
            val limits = BoundedDwarfInterfaceFactLimits(maximumTypeDepth = 2)
            assertEquals(2, scan(root, fixture(false), limits).types.size)
            val failure = assertFailsWith<FullTreeControlException> { scan(root, fixture(true), limits) }
            assertTrue(failure.message.orEmpty().contains("depth bound"))
            assertEquals(3, scan(root, fixture(true), limits.copy(maximumTypeDepth = 3)).types.size)
        }

    @Test
    fun `type graph collections and fact payloads are deeply immutable snapshots`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val fixture = typeElf(
                emitted("entry", "structure"),
                die("structure", 0x13, listOf(text(0x03, "Record")), listOf(
                    die("member", 0x0d, listOf(reference(0x49, "int"))),
                )),
                integerType(),
            )
            val facts = scan(root, fixture)
            val node = facts.types.getValue(fixture.locator("structure"))
            val child = node.children.single()
            val before = facts.canonicalBytes()
            assertFailsWith<UnsupportedOperationException> { (facts.types as MutableMap<String, DwarfInterfaceTypeNode>).clear() }
            assertFailsWith<UnsupportedOperationException> { (node.attributes as MutableMap<Long, DwarfInterfaceFact<String>>).clear() }
            assertFailsWith<UnsupportedOperationException> { (node.children as MutableList<DwarfInterfaceTypeChild>).clear() }
            assertFailsWith<UnsupportedOperationException> { (node.reasons as MutableList<String>).add("forged") }
            assertFailsWith<UnsupportedOperationException> { (node.name.values as MutableList<String>).add("forged") }
            assertFailsWith<UnsupportedOperationException> { (node.name.evidence as MutableList<String>).add("forged") }
            assertFailsWith<UnsupportedOperationException> { (node.name.reasons as MutableList<String>).add("forged") }
            assertFailsWith<UnsupportedOperationException> { (child.attributes as MutableMap<Long, DwarfInterfaceFact<String>>).clear() }
            assertFailsWith<UnsupportedOperationException> { (child.type.values as MutableList<String>).add("forged") }
            assertFailsWith<UnsupportedOperationException> { (child.reasons as MutableList<String>).add("forged") }
            assertContentEquals(before, facts.canonicalBytes())

            val attributes = node.attributes.toMutableMap()
            val children = node.children.toMutableList()
            val reasons = mutableListOf("retained")
            val snapshot = DwarfInterfaceTypeNode(node.id, node.tag, node.name, node.byteSize,
                node.encoding, node.type, attributes, children, reasons)
            attributes.clear()
            children.clear()
            reasons.clear()
            assertEquals(node.attributes, snapshot.attributes)
            assertEquals(node.children, snapshot.children)
            assertEquals(listOf("retained"), snapshot.reasons)
            val mutableValues = mutableListOf("original")
            val fact = DwarfInterfaceFact(DwarfInterfaceFactState.KNOWN, mutableValues)
            mutableValues[0] = "changed"
            known(fact, "original")
        }

    private fun known(fact: DwarfInterfaceFact<String>, value: String) {
        assertEquals(DwarfInterfaceFactState.KNOWN, fact.state)
        assertEquals(listOf(value), fact.values)
    }

    private fun target() = OracleJson.parse(Files.readAllBytes(Path.of("oracle/targets/sysv-amd64-v1.json"))) as JsonObject

    private fun scan(root: Path, fixture: TypeGraphElf,
        limits: BoundedDwarfInterfaceFactLimits = BoundedDwarfInterfaceFactLimits()): BoundedDwarfInterfaceFacts {
        val path = writeElf(root.resolve("interface-types.elf"), fixture.bytes)
        return StableControlFile.open(path, fixture.bytes.size.toLong(), "interface type fixture").use { artifact ->
            BoundedDwarfInterfaceFactScanner.scan(artifact, root, limits = limits)
        }
    }
}

/** Independent byte-level fixture: no recovered model, symbol table, compiler, or DWARF parser helper. */
internal data class TypeGraphDie(
    val label: String,
    val tag: Long,
    val attributes: List<TypeGraphAttribute>,
    val children: List<TypeGraphDie>,
)
internal data class TypeGraphAttribute(
    val name: Long,
    val form: Long,
    val bytes: ByteArray,
    val target: String? = null,
    val addend: Int = 0,
    val implicitConstant: Long? = null,
)
internal data class TypeGraphElf(
    val bytes: ByteArray,
    val offsets: Map<String, Int>,
    val unitOffsets: Map<String, Int> = emptyMap(),
) {
    fun locator(label: String): String =
        ".debug_info:cu=0x${(unitOffsets[label] ?: 0).toString(16)}:die=0x${offsets.getValue(label).toString(16)}"
}

internal data class TypeGraphCompilationUnit(
    val label: String,
    val declarations: List<TypeGraphDie>,
    val rootAttributes: List<TypeGraphAttribute> = emptyList(),
)

internal fun die(label: String, tag: Long, attributes: List<TypeGraphAttribute> = emptyList(),
    children: List<TypeGraphDie> = emptyList()) = TypeGraphDie(label, tag, attributes, children)
internal fun text(name: Long, value: String) = raw(name, FULL_TREE_DW_FORM_STRING, value.toByteArray(Charsets.UTF_8) + byteArrayOf(0))
internal fun number(name: Long, value: Long) = raw(name, FULL_TREE_DW_FORM_DATA1, fixed(value, 1))
internal fun address(name: Long, value: Long) = raw(name, FULL_TREE_DW_FORM_ADDR, fixed(value, 8))
internal fun flag(name: Long) = raw(name, FULL_TREE_DW_FORM_FLAG_PRESENT, byteArrayOf())
internal fun raw(name: Long, form: Long, bytes: ByteArray) = TypeGraphAttribute(name, form, bytes)
internal fun reference(name: Long, target: String, addend: Int = 0) =
    TypeGraphAttribute(name, FULL_TREE_DW_FORM_REF4, ByteArray(4), target, addend)
internal fun integerType(label: String = "int") = die(label, 0x24,
    listOf(text(0x03, "int"), number(0x0b, 4), number(0x3e, 5)))
internal fun emitted(label: String, returnType: String?, ordinal: Int = 0) = die(label, 0x2e,
    listOf(text(0x03, label), address(0x11, 0x400100L + ordinal * 8L)) +
        listOfNotNull(returnType?.let { reference(0x49, it) }))

internal fun typeElf(
    vararg declarations: TypeGraphDie,
    version: Int = 4,
    rootAttributes: List<TypeGraphAttribute> = emptyList(),
    additionalSections: Map<String, ByteArray> = emptyMap(),
): TypeGraphElf = typeElfUnits(
    listOf(TypeGraphCompilationUnit("unit", declarations.toList(), rootAttributes)), version, additionalSections,
)

internal fun typeElfUnits(
    units: List<TypeGraphCompilationUnit>,
    version: Int = 4,
    additionalSections: Map<String, ByteArray> = emptyMap(),
): TypeGraphElf {
    val headerBytes = if (version == 5) 12 else 11
    val roots = units.map { unit -> die(unit.label, 0x11,
        listOf(text(0x03, "types.c"), number(0x13, 0x0c)) + unit.rootAttributes, unit.declarations) }
    val flattened = ArrayList<TypeGraphDie>()
    fun collect(node: TypeGraphDie) {
        require(flattened.none { it.label == node.label })
        flattened += node
        node.children.forEach(::collect)
    }
    roots.forEach(::collect)
    val codes = flattened.mapIndexed { index, node -> node.label to (index + 1).toLong() }.toMap()
    val abbrev = ByteArrayOutputStream()
    flattened.forEach { node ->
        abbrev.write(uleb(codes.getValue(node.label)))
        abbrev.write(uleb(node.tag))
        abbrev.write(if (node.children.isEmpty()) 0 else 1)
        node.attributes.forEach { attribute ->
            abbrev.write(uleb(attribute.name))
            abbrev.write(uleb(attribute.form))
            if (attribute.form == FULL_TREE_DW_FORM_IMPLICIT_CONST) {
                abbrev.write(sleb(requireNotNull(attribute.implicitConstant)))
            }
        }
        abbrev.write(0)
        abbrev.write(0)
    }
    abbrev.write(0)
    val infoBytes = ByteArrayOutputStream()
    val offsets = LinkedHashMap<String, Int>()
    val unitOffsets = LinkedHashMap<String, Int>()
    val patches = ArrayList<Triple<Int, Int, TypeGraphAttribute>>()
    for (root in roots) {
        val unitOffset = infoBytes.size()
        val dies = ByteArrayOutputStream()
        fun encode(node: TypeGraphDie) {
            offsets[node.label] = unitOffset + headerBytes + dies.size()
            unitOffsets[node.label] = unitOffset
            dies.write(uleb(codes.getValue(node.label)))
            node.attributes.forEach { attribute ->
                if (attribute.target != null) patches += Triple(unitOffset + headerBytes + dies.size(), unitOffset, attribute)
                dies.write(attribute.bytes)
            }
            node.children.forEach(::encode)
            if (node.children.isNotEmpty()) dies.write(0)
        }
        encode(root)
        val header = if (version == 5) fixed(5, 2) + byteArrayOf(1, 8) + fixed(0, 4)
            else fixed(version.toLong(), 2) + fixed(0, 4) + byteArrayOf(8)
        val unit = header + dies.toByteArray()
        infoBytes.write(fixed(unit.size.toLong(), 4))
        infoBytes.write(unit)
    }
    val info = infoBytes.toByteArray()
    patches.forEach { (offset, unitOffset, attribute) ->
        val target = requireNotNull(attribute.target)
        val value = if (attribute.form == FULL_TREE_DW_FORM_REF_ADDR) {
            offsets.getValue(target)
        } else {
            require(unitOffsets.getValue(target) == unitOffset) { "local reference crosses a fixture compilation unit" }
            offsets.getValue(target) - unitOffset
        }
        fixed((value + attribute.addend).toLong(), 4).copyInto(info, offset)
    }
    val sections = linkedMapOf(".text" to ByteArray(0x100) { 0x90.toByte() },
        ".debug_info" to info, ".debug_abbrev" to abbrev.toByteArray())
    require(additionalSections.keys.none { it in sections || it == ".shstrtab" })
    sections.putAll(additionalSections.toSortedMap())
    val names = ByteArrayOutputStream().apply { write(0) }
    val nameOffsets = (sections.keys + ".shstrtab").associateWith { name ->
        names.size().also { names.write(name.toByteArray(Charsets.US_ASCII)); names.write(0) }
    }
    sections[".shstrtab"] = names.toByteArray()
    var cursor = 0x100
    val sectionOffsets = sections.mapValues { (_, content) -> cursor.also { cursor += content.size } }
    val sectionTable = (cursor + 7) / 8 * 8
    val sectionCount = sections.size + 1
    val bytes = ByteArray(sectionTable + sectionCount * 64)
    byteArrayOf(0x7f, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte(), 2, 1, 1).copyInto(bytes)
    fun put(offset: Int, value: Long, width: Int) = fixed(value, width).copyInto(bytes, offset)
    put(16, 2, 2) // ET_EXEC
    put(18, 62, 2) // x86-64
    put(20, 1, 4)
    put(24, 0x400100, 8)
    put(32, 64, 8)
    put(40, sectionTable.toLong(), 8)
    put(52, 64, 2)
    put(54, 56, 2)
    put(56, 1, 2)
    put(58, 64, 2)
    put(60, sectionCount.toLong(), 2)
    put(62, sections.size.toLong(), 2)
    put(64, 1, 4) // PT_LOAD
    put(68, 5, 4) // PF_R | PF_X
    put(80, 0x400000, 8)
    put(88, 0x400000, 8)
    put(96, bytes.size.toLong(), 8)
    put(104, bytes.size.toLong(), 8)
    put(112, 0x1000, 8)
    sections.entries.forEachIndexed { index, (name, content) ->
        val offset = sectionOffsets.getValue(name)
        content.copyInto(bytes, offset)
        val header = sectionTable + (index + 1) * 64
        put(header, nameOffsets.getValue(name).toLong(), 4)
        put(header + 4, if (name == ".shstrtab") 3 else 1, 4)
        put(header + 8, if (name == ".text") 6 else 0, 8)
        put(header + 16, if (name == ".text") 0x400100 else 0, 8)
        put(header + 24, offset.toLong(), 8)
        put(header + 32, content.size.toLong(), 8)
        put(header + 48, if (name == ".text") 16 else 1, 8)
    }
    return TypeGraphElf(bytes, offsets, unitOffsets)
}

internal fun fixed(value: Long, width: Int): ByteArray = ByteArray(width) { index -> (value ushr (index * 8)).toByte() }
internal fun uleb(value: Long): ByteArray {
    require(value >= 0)
    var remaining = value
    val bytes = ByteArrayOutputStream()
    do {
        val part = (remaining and 0x7f).toInt()
        remaining = remaining ushr 7
        bytes.write(part or if (remaining == 0L) 0 else 0x80)
    } while (remaining != 0L)
    return bytes.toByteArray()
}

private fun sleb(value: Long): ByteArray {
    var remaining = value
    val bytes = ByteArrayOutputStream()
    do {
        val part = (remaining and 0x7f).toInt()
        remaining = remaining shr 7
        val more = !((remaining == 0L && (part and 0x40) == 0) || (remaining == -1L && (part and 0x40) != 0))
        bytes.write(part or if (more) 0x80 else 0)
    } while (more)
    return bytes.toByteArray()
}
