package decompengine.oracle.fulltree

import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class BoundedDwarfGlobalSyntheticFactsTest {
    @Test
    fun `bounded scalar evidence accounting includes the retained origin specification DAG`() =
        inInterfaceFixtureDirectory { root ->
            val shared = (0 until 31).map { index ->
                val references = if (index < 15) listOf(
                    reference(0x31, "shared-${index * 2 + 1}"),
                    reference(0x47, "shared-${index * 2 + 2}"),
                ) else emptyList()
                variable("shared-$index", references)
            }
            val roots = (0 until 256).map { index -> variable("root-$index", listOf(
                reference(0x31, "shared-0"), absoluteLocation(0x400180L + index),
            )) }
            val fixture = typeElf(*(roots + shared).toTypedArray())
            val facts = scan(root, fixture)
            assertEquals(287, facts.globals.size)
            val rootFact = facts.global(fixture, "root-0")
            assertEquals(32, rootFact.origins.size)
            assertEquals(16, rootFact.external.evidence.size)

            val integralFacts = facts.globals.flatMap { global ->
                listOf(global.language, global.external, global.declaration, global.artificial,
                    global.visibility, global.byteSize, global.alignment)
            }
            fun strings(fact: DwarfInterfaceFact<String>) = fact.values + fact.evidence + fact.reasons
            val scalarTextPayloadLowerBound = integralFacts.sumOf { fact ->
                strings(fact).sumOf { text -> text.length.toLong() * 2L }
            }
            val modeledScalarFactBytes = integralFacts.sumOf { fact ->
                strings(fact).fold(192L) { total, text -> total + 32L + text.length.toLong() * 2L }
            }
            assertTrue(scalarTextPayloadLowerBound > 1024L * 1024L,
                "expected a megabyte-scale retained scalar evidence lower bound, got $scalarTextPayloadLowerBound")
            assertTrue(modeledScalarFactBytes > scalarTextPayloadLowerBound)

            val tightLimit = facts.modeledRetainedFactBytes - modeledScalarFactBytes + 64L * 1024L
            val failure = assertFailsWith<FullTreeControlException> {
                scan(root, fixture, BoundedDwarfInterfaceFactLimits(maximumRetainedFactBytes = tightLimit))
            }
            assertTrue(failure.message.orEmpty().contains("DWARF interface integral exceeds retained fact bound"),
                failure.message)
        }

    @Test
    fun `implicit constant globals retain negative and positive signed values from abbreviations`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val fixture = typeElf(
                variable("negative", listOf(raw(0x1c, FULL_TREE_DW_FORM_IMPLICIT_CONST, byteArrayOf())
                    .copy(implicitConstant = -42L))),
                variable("positive", listOf(raw(0x1c, FULL_TREE_DW_FORM_IMPLICIT_CONST, byteArrayOf())
                    .copy(implicitConstant = 17L))),
                version = 5,
            )
            val facts = scan(root, fixture)
            assertEquals(2, facts.globals.size)
            known(facts.global(fixture, "negative").constant, "signed:-42")
            known(facts.global(fixture, "positive").constant, "signed:17")
        }

    @Test
    fun `direct and indirect flag forms retain known zero and one for prototypes and global flags`(): Unit =
        inInterfaceFixtureDirectory { root ->
            data class FlagCase(val label: String, val form: Long, val payload: ByteArray, val expected: String)
            val cases = listOf(
                FlagCase("explicitZero", FULL_TREE_DW_FORM_FLAG, byteArrayOf(0), "0"),
                FlagCase("explicitOne", FULL_TREE_DW_FORM_FLAG, byteArrayOf(1), "1"),
                FlagCase("present", FULL_TREE_DW_FORM_FLAG_PRESENT, byteArrayOf(), "1"),
                FlagCase("indirectZero", FULL_TREE_DW_FORM_INDIRECT, uleb(FULL_TREE_DW_FORM_FLAG) + byteArrayOf(0), "0"),
                FlagCase("indirectOne", FULL_TREE_DW_FORM_INDIRECT, uleb(FULL_TREE_DW_FORM_FLAG) + byteArrayOf(1), "1"),
                FlagCase("indirectPresent", FULL_TREE_DW_FORM_INDIRECT, uleb(FULL_TREE_DW_FORM_FLAG_PRESENT), "1"),
            )
            val declarations = cases.flatMapIndexed { index, case ->
                fun encoded(name: Long) = raw(name, case.form, case.payload)
                listOf(
                    die("function_${case.label}", 0x2e, listOf(text(0x03, "function_${case.label}"),
                        address(0x11, 0x400100L + index * 8L), encoded(0x27))),
                    variable("global_${case.label}", listOf(encoded(0x3f), encoded(0x3c))),
                )
            }
            val fixture = typeElf(*declarations.toTypedArray())
            val facts = scan(root, fixture)
            assertEquals(cases.size, facts.functions.size)
            assertEquals(cases.size, facts.globals.size)
            for (case in cases) {
                val function = facts.functions.single { it.locator == fixture.locator("function_${case.label}") }
                val global = facts.global(fixture, "global_${case.label}")
                known(function.prototyped, case.expected)
                known(global.external, case.expected)
                known(global.declaration, case.expected)
            }
        }

    @Test
    fun `every raw variable survives file namespace class function block and unknown ancestry`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val fixture = typeElf(
                variable("file", listOf(absoluteLocation(0x400180))),
                variable("declaration", listOf(flag(0x3c))),
                die("namespace", 0x39, listOf(text(0x03, "Space")), listOf(
                    variable("namespaced", listOf(absoluteLocation(0x400188))),
                )),
                die("class", 0x02, listOf(text(0x03, "Owner")), listOf(
                    variable("classMember", listOf(absoluteLocation(0x400190))),
                )),
                die("function", 0x2e, listOf(text(0x03, "function"), address(0x11, 0x400100)), listOf(
                    variable("automatic", listOf(location(byteArrayOf(0x91.toByte(), 0x78)))),
                    die("block", 0x0b, children = listOf(variable("blockLocal", listOf(location(byteArrayOf(0x50)))))),
                )),
                die("unknownScope", 0x4080, listOf(text(0x03, "VendorScope")), listOf(variable("unknown"))),
            )
            val facts = scan(root, fixture)
            val labels = listOf("file", "declaration", "namespaced", "classMember", "automatic", "blockLocal", "unknown")
            assertEquals(7, facts.globals.size)
            assertEquals(labels.map(fixture::locator).toSet(), facts.globals.map { it.locator }.toSet())
            for ((label, scope) in listOf("file" to "file", "declaration" to "file",
                "namespaced" to "namespace", "classMember" to "class", "automatic" to "function", "blockLocal" to "block")) {
                known(facts.global(fixture, label).scope, scope)
            }
            val unknown = facts.global(fixture, "unknown")
            assertEquals(DwarfInterfaceFactState.UNKNOWN, unknown.scope.state)
            assertTrue(unknown.scope.values.isEmpty())
            assertTrue(unknown.scopes.any { it.locator == fixture.locator("unknownScope") && it.tag == 0x4080L })
            assertFalse(unknown.scope.values.contains("file"))
            assertContentEquals(facts.canonicalBytes(), scan(root, fixture).canonicalBytes())
        }

    @Test
    fun `global-only input resolves shared types without requiring emitted functions`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val fixture = typeElf(
                variable("global", listOf(reference(0x49, "alias"), absoluteLocation(0x400180))),
                die("alias", 0x16, listOf(text(0x03, "Count"), reference(0x49, "int"))),
                integerType(),
            )
            val facts = scan(root, fixture)
            assertTrue(facts.functions.isEmpty())
            assertTrue(facts.objectSymbols.isEmpty())
            assertEquals(1, facts.globals.size)
            assertEquals(2, facts.types.size)
            known(facts.globals.single().type, fixture.locator("alias"))
            known(facts.types.getValue(fixture.locator("alias")).type, fixture.locator("int"))
        }

    @Test
    fun `missing location type and constant remain absent without invented storage`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val fixture = typeElf(variable("missing"), variable("declaration", listOf(flag(0x3c))))
            val facts = scan(root, fixture)
            assertEquals(2, facts.globals.size)
            for (global in facts.globals) {
                assertEquals(DwarfInterfaceFactState.ABSENT, global.location.state)
                assertEquals(DwarfInterfaceFactState.ABSENT, global.type.state)
                assertEquals(DwarfInterfaceFactState.ABSENT, global.constant.state)
                assertTrue(global.address.values.isEmpty())
                assertTrue(global.rva.values.isEmpty())
                assertFalse(global.storage.values.contains("static-storage"))
            }
            known(facts.global(fixture, "declaration").declaration, "1")
        }

    @Test
    fun `definition inherits declaration identity and type but never its declaration flag`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val fixture = typeElf(
                variable("declaration", listOf(text(0x6e, "_ZN5Space5countE"), reference(0x49, "int"), flag(0x3c), flag(0x3f))),
                die("definition", 0x34, listOf(reference(0x47, "declaration"), absoluteLocation(0x400180))),
                integerType(),
            )
            val facts = scan(root, fixture)
            assertEquals(2, facts.globals.size)
            val definition = facts.global(fixture, "definition")
            known(definition.sourceName, "declaration")
            known(definition.linkageName, "_ZN5Space5countE")
            known(definition.type, fixture.locator("int"))
            known(definition.external, "1")
            assertEquals(DwarfInterfaceFactState.ABSENT, definition.declaration.state)
            assertTrue(fixture.locator("declaration") in definition.origins)
            known(definition.address, "0x400180")
            known(definition.rva, "0x180")
        }

    @Test
    fun `out of line class variable uses inherited class scope with ancestry owners`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val fixture = typeElf(
                die("namespace", 0x39, listOf(text(0x03, "Space")), listOf(
                    die("class", 0x02, listOf(text(0x03, "Owner")), listOf(
                        variable("declaration", listOf(flag(0x3c), reference(0x49, "int"))),
                    )),
                )),
                die("definition", 0x34, listOf(reference(0x47, "declaration"), absoluteLocation(0x400180))),
                integerType(),
            )
            val facts = scan(root, fixture)
            assertEquals(2, facts.globals.size)
            val definition = facts.global(fixture, "definition")
            known(definition.scope, "class")
            assertTrue(definition.scopes.any { it.locator == fixture.locator("class") &&
                it.ownerLocator == fixture.locator("declaration") })
            assertTrue(definition.scopes.any { it.locator == fixture.locator("unit") &&
                it.ownerLocator == fixture.locator("definition") })
            known(definition.type, fixture.locator("int"))
        }

    @Test
    fun `conflicting non-file ancestry remains ambiguous and preserves both chains`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val fixture = typeElf(
                die("namespace", 0x39, listOf(text(0x03, "Space")), listOf(variable("left", listOf(flag(0x3c))))),
                die("class", 0x02, listOf(text(0x03, "Owner")), listOf(variable("right", listOf(flag(0x3c))))),
                variable("definition", listOf(reference(0x47, "left"), reference(0x31, "right"))),
            )
            val facts = scan(root, fixture)
            assertEquals(3, facts.globals.size)
            val definition = facts.global(fixture, "definition")
            assertEquals(DwarfInterfaceFactState.AMBIGUOUS, definition.scope.state)
            assertEquals(setOf("namespace", "class"), definition.scope.values.toSet())
            assertTrue(definition.scopes.any { it.locator == fixture.locator("namespace") &&
                it.ownerLocator == fixture.locator("left") })
            assertTrue(definition.scopes.any { it.locator == fixture.locator("class") &&
                it.ownerLocator == fixture.locator("right") })
        }

    @Test
    fun `absolute locations retain bytes forms and static storage evidence`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val expression = byteArrayOf(0x03) + fixed(0x400180, 8)
            val fixture = typeElf(variable("global", listOf(location(expression))))
            val global = scan(root, fixture).globals.single()
            known(global.address, "0x400180")
            known(global.rva, "0x180")
            known(global.storage, "static-storage")
            assertEquals(DwarfInterfaceFactState.KNOWN, global.location.state)
            val captured = global.location.values.single()
            assertEquals("address", captured.kind)
            assertEquals(FULL_TREE_DW_FORM_EXPRLOC, captured.declaredForm)
            assertEquals(FULL_TREE_DW_FORM_EXPRLOC, captured.resolvedForm)
            assertEquals(hexBytes(expression), captured.expressionHex)
            assertTrue(captured.sourceLocator.startsWith(fixture.locator("global")))
        }

    @Test
    fun `indexed address resolves the compilation unit address table`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val table = fixed(20, 4) + fixed(5, 2) + byteArrayOf(8, 0) + fixed(0x400180, 8) + fixed(0x400198, 8)
            val fixture = typeElf(
                variable("indexed", listOf(location(byteArrayOf(0xa1.toByte(), 1)))),
                version = 5,
                rootAttributes = listOf(raw(0x73, FULL_TREE_DW_FORM_SEC_OFFSET, fixed(8, 4))),
                additionalSections = mapOf(".debug_addr" to table),
            )
            val global = scan(root, fixture).globals.single()
            known(global.address, "0x400198")
            known(global.rva, "0x198")
            known(global.storage, "static-storage")
            assertEquals("a101", global.location.values.single().expressionHex)
            assertEquals("address-index", global.location.values.single().kind)
        }

    @Test
    fun `indirect expression forms survive and address prefixes never hide unsupported tails`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val addressExpression = byteArrayOf(0x03) + fixed(0x400180, 8)
            val valueExpression = addressExpression + byteArrayOf(0x9f.toByte()) // DW_OP_stack_value changes its meaning.
            val fixture = typeElf(
                variable("indirect", listOf(raw(0x02, FULL_TREE_DW_FORM_INDIRECT,
                    uleb(FULL_TREE_DW_FORM_EXPRLOC) + uleb(addressExpression.size.toLong()) + addressExpression))),
                variable("unsupportedTail", listOf(location(valueExpression))),
            )
            val facts = scan(root, fixture)
            assertEquals(2, facts.globals.size)
            val indirect = facts.global(fixture, "indirect")
            known(indirect.address, "0x400180")
            known(indirect.storage, "static-storage")
            val captured = indirect.location.values.single()
            assertEquals(FULL_TREE_DW_FORM_INDIRECT, captured.declaredForm)
            assertEquals(FULL_TREE_DW_FORM_EXPRLOC, captured.resolvedForm)
            assertEquals(hexBytes(addressExpression), captured.expressionHex)
            val unsupported = facts.global(fixture, "unsupportedTail")
            assertEquals(DwarfInterfaceFactState.UNKNOWN, unsupported.location.state)
            assertEquals(DwarfInterfaceFactState.UNKNOWN, unsupported.address.state)
            assertTrue(unsupported.address.values.isEmpty())
            assertFalse(unsupported.storage.values.contains("static-storage"))
            assertEquals("expression-unsupported", unsupported.location.values.single().kind)
            assertEquals(hexBytes(valueExpression), unsupported.location.values.single().expressionHex)
        }

    @Test
    fun `unsupported expressions and location lists remain unknown with raw evidence`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val expression = byteArrayOf(0x9c.toByte(), 0x23, 0x04)
            val fixture = typeElf(
                variable("expression", listOf(location(expression))),
                variable("offset", listOf(raw(0x02, FULL_TREE_DW_FORM_SEC_OFFSET, fixed(68, 4)))),
                variable("index", listOf(raw(0x02, FULL_TREE_DW_FORM_LOCLISTX, uleb(3)))),
                version = 5,
            )
            val facts = scan(root, fixture)
            assertEquals(3, facts.globals.size)
            for (global in facts.globals) {
                assertEquals(DwarfInterfaceFactState.UNKNOWN, global.location.state)
                assertEquals(DwarfInterfaceFactState.UNKNOWN, global.address.state)
                assertTrue(global.address.values.isEmpty())
                assertFalse(global.storage.values.contains("static-storage"))
            }
            assertEquals(hexBytes(expression), facts.global(fixture, "expression").location.values.single().expressionHex)
            assertEquals("expression-unsupported", facts.global(fixture, "expression").location.values.single().kind)
            assertEquals(FULL_TREE_DW_FORM_SEC_OFFSET, facts.global(fixture, "offset").location.values.single().declaredForm)
            assertEquals(FULL_TREE_DW_FORM_LOCLISTX, facts.global(fixture, "index").location.values.single().declaredForm)
            assertEquals("location-list", facts.global(fixture, "offset").location.values.single().kind)
            assertEquals("0x44", facts.global(fixture, "offset").location.values.single().operand)
            assertEquals("0x3", facts.global(fixture, "index").location.values.single().operand)
        }

    @Test
    fun `frame and register locations imply automatic storage only under function ancestry`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val fixture = typeElf(
                variable("fileRegister", listOf(location(byteArrayOf(0x50)))),
                die("function", 0x2e, listOf(text(0x03, "function"), address(0x11, 0x400100)), listOf(
                    variable("frame", listOf(location(byteArrayOf(0x91.toByte(), 0x78)))),
                    variable("register", listOf(location(byteArrayOf(0x50)))),
                    variable("localStatic", listOf(absoluteLocation(0x400180))),
                )),
            )
            val facts = scan(root, fixture)
            assertEquals(4, facts.globals.size)
            known(facts.global(fixture, "frame").storage, "automatic")
            known(facts.global(fixture, "register").storage, "automatic")
            known(facts.global(fixture, "localStatic").storage, "static-storage")
            assertEquals("frame-relative", facts.global(fixture, "frame").location.values.single().kind)
            assertEquals("register", facts.global(fixture, "register").location.values.single().kind)
            assertFalse(facts.global(fixture, "fileRegister").storage.values.contains("automatic"))
            for (label in listOf("frame", "register")) {
                val global = facts.global(fixture, label)
                assertEquals(DwarfInterfaceFactState.UNKNOWN, global.address.state)
                assertTrue(global.address.values.isEmpty())
            }
        }

    @Test
    fun `complete TLS expression records thread local storage without inventing an address`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val fixture = typeElf(
                variable("tls", listOf(location(byteArrayOf(0x10, 0x07, 0x9b.toByte())))),
                variable("unsupportedTail", listOf(location(byteArrayOf(0x10, 0x07, 0x9b.toByte(), 0x96.toByte())))),
            )
            val facts = scan(root, fixture)
            val tls = facts.global(fixture, "tls")
            known(tls.storage, "thread-local")
            known(tls.tlsOffset, "0x7")
            assertEquals("tls-offset", tls.location.values.single().kind)
            assertEquals(DwarfInterfaceFactState.UNKNOWN, tls.address.state)
            assertTrue(tls.address.values.isEmpty())
            assertTrue(tls.rva.values.isEmpty())
            assertEquals("10079b", tls.location.values.single().expressionHex)
            assertEquals(DwarfInterfaceFactState.UNKNOWN, facts.global(fixture, "unsupportedTail").location.state)
            assertFalse(facts.global(fixture, "unsupportedTail").storage.values.contains("thread-local"))
        }

    @Test
    fun `truncated operands in supported singleton locations are malformed`(): Unit =
        inInterfaceFixtureDirectory { root ->
            for (expression in listOf(byteArrayOf(0x03, 1), byteArrayOf(0xa1.toByte()),
                byteArrayOf(0x91.toByte(), 0x80.toByte()))) {
                val fixture = typeElf(variable("truncated", listOf(location(expression))), version = 5)
                assertFailsWith<FullTreeControlException> { scan(root, fixture) }
            }
        }

    @Test
    fun `raw signed unsigned UTF8 and block constants remain distinguishable`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val fixture = typeElf(
                variable("unsigned", listOf(raw(0x1c, FULL_TREE_DW_FORM_DATA8, fixed(-1, 8)))),
                variable("signed", listOf(raw(0x1c, FULL_TREE_DW_FORM_SDATA, byteArrayOf(0x56)))),
                variable("string", listOf(text(0x1c, "π"))),
                variable("bytes", listOf(raw(0x1c, FULL_TREE_DW_FORM_BLOCK1, byteArrayOf(2, 0xff.toByte(), 0)))),
            )
            val facts = scan(root, fixture)
            assertEquals(4, facts.globals.size)
            known(facts.global(fixture, "unsigned").constant, "unsigned:18446744073709551615")
            known(facts.global(fixture, "signed").constant, "signed:-42")
            known(facts.global(fixture, "string").constant, "utf8:π")
            known(facts.global(fixture, "bytes").constant, "bytes:ff00")
        }

    @Test
    fun `direct and indirect data16 global constants retain the supported unsigned value`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val maximum = fixed(-1, 8) + ByteArray(8)
            val fixture = typeElf(
                variable("direct", listOf(raw(0x1c, FULL_TREE_DW_FORM_DATA16, maximum))),
                variable("indirect", listOf(raw(0x1c, FULL_TREE_DW_FORM_INDIRECT,
                    uleb(FULL_TREE_DW_FORM_DATA16) + maximum))),
                variable("zero", listOf(raw(0x1c, FULL_TREE_DW_FORM_DATA16, ByteArray(16)))),
                version = 5,
            )
            val facts = scan(root, fixture)
            assertEquals(3, facts.globals.size)
            for (label in listOf("direct", "indirect")) {
                val constant = facts.global(fixture, label).constant
                known(constant, "unsigned:18446744073709551615")
                assertEquals(listOf("${fixture.locator(label)}:attribute=0x1c"), constant.evidence)
                assertTrue(constant.reasons.isEmpty())
            }
            known(facts.global(fixture, "zero").constant, "unsigned:0")
        }

    @Test
    fun `explicit variable attributes are retained as source facts`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val fixture = typeElf(variable("object", listOf(text(0x6e, "object_symbol"), flag(0x3f), flag(0x34),
                number(0x17, 2), number(0x0b, 8), number(0x88, 8), absoluteLocation(0x400180))))
            val global = scan(root, fixture).globals.single()
            known(global.sourceName, "object")
            known(global.linkageName, "object_symbol")
            known(global.external, "1")
            known(global.artificial, "1")
            known(global.visibility, "2")
            known(global.byteSize, "8")
            known(global.alignment, "8")
            known(global.language, "12")
        }

    @Test
    fun `unavailable supplementary variable declaration cannot become absent inherited evidence`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val fixture = typeElf(variable("incomplete", listOf(raw(0x47, FULL_TREE_DW_FORM_REF_SUP4, fixed(7, 4)))), version = 5)
            val global = scan(root, fixture).globals.single()
            known(global.sourceName, "incomplete")
            assertEquals(DwarfInterfaceFactState.UNKNOWN, global.type.state)
            assertEquals(DwarfInterfaceFactState.UNKNOWN, global.location.state)
            assertTrue(global.reasons.any { it.contains("unsupported-origin-specification-reference") })
        }

    @Test
    fun `global type references still require a real DIE boundary`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val fixture = typeElf(variable("badType", listOf(reference(0x49, "int", addend = 1))), integerType())
            assertFailsWith<FullTreeControlException> { scan(root, fixture) }
        }

    @Test
    fun `global count expression scope and type limits fail closed`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val fixture = typeElf(variable("one"), variable("two"))
            assertEquals(2, scan(root, fixture, BoundedDwarfInterfaceFactLimits(maximumGlobals = 2)).globals.size)
            assertFailsWith<FullTreeControlException> { scan(root, fixture, BoundedDwarfInterfaceFactLimits(maximumGlobals = 1)) }
            assertFailsWith<FullTreeControlException> { scan(root, fixture, BoundedDwarfInterfaceFactLimits(maximumOutputBytes = 100)) }
            val expression = typeElf(variable("absolute", listOf(absoluteLocation(0x400180))))
            assertEquals(1, scan(root, expression, BoundedDwarfInterfaceFactLimits(maximumLocationExpressionBytes = 9)).globals.size)
            assertFailsWith<FullTreeControlException> {
                scan(root, expression, BoundedDwarfInterfaceFactLimits(maximumLocationExpressionBytes = 8))
            }
            val scoped = typeElf(die("outer", 0x39, children = listOf(
                die("inner", 0x39, children = listOf(variable("nested"))),
            )))
            assertFailsWith<FullTreeControlException> { scan(root, scoped, BoundedDwarfInterfaceFactLimits(maximumScopeDepth = 1)) }
            val typed = typeElf(variable("typed", listOf(reference(0x49, "alias"))),
                die("alias", 0x16, listOf(reference(0x49, "int"))), integerType())
            assertFailsWith<FullTreeControlException> { scan(root, typed, BoundedDwarfInterfaceFactLimits(maximumTypes = 1)) }
        }

    @Test
    fun `globals scopes locations and inherited fact lists are immutable`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val fixture = typeElf(die("namespace", 0x39, listOf(text(0x03, "Space")), listOf(
                variable("object", listOf(absoluteLocation(0x400180))),
            )))
            val facts = scan(root, fixture)
            val global = facts.globals.single()
            val before = facts.canonicalBytes()
            assertFailsWith<UnsupportedOperationException> { (facts.globals as MutableList<DwarfGlobalVariableFacts>).clear() }
            assertFailsWith<UnsupportedOperationException> { (global.scopes as MutableList<DwarfGlobalScope>).clear() }
            assertFailsWith<UnsupportedOperationException> { (global.origins as MutableList<String>).add("forged") }
            assertFailsWith<UnsupportedOperationException> { (global.reasons as MutableList<String>).add("forged") }
            assertFailsWith<UnsupportedOperationException> { (global.location.values as MutableList<DwarfGlobalLocation>).clear() }
            assertFailsWith<UnsupportedOperationException> { (global.location.evidence as MutableList<String>).clear() }
            assertFailsWith<UnsupportedOperationException> { (global.storage.values as MutableList<String>).add("automatic") }
            val namedScope = global.scopes.single { it.locator == fixture.locator("namespace") }
            assertFailsWith<UnsupportedOperationException> { (namedScope.name.values as MutableList<String>).add("forged") }
            assertContentEquals(before, facts.canonicalBytes())
        }

    private fun variable(label: String, attributes: List<TypeGraphAttribute> = emptyList()) =
        die(label, 0x34, listOf(text(0x03, label)) + attributes)

    private fun location(bytes: ByteArray): TypeGraphAttribute =
        raw(0x02, FULL_TREE_DW_FORM_EXPRLOC, uleb(bytes.size.toLong()) + bytes)

    private fun absoluteLocation(value: Long): TypeGraphAttribute = location(byteArrayOf(0x03) + fixed(value, 8))

    private fun known(fact: DwarfInterfaceFact<String>, value: String) {
        assertEquals(DwarfInterfaceFactState.KNOWN, fact.state)
        assertEquals(listOf(value), fact.values)
    }

    private fun BoundedDwarfInterfaceFacts.global(fixture: TypeGraphElf, label: String): DwarfGlobalVariableFacts =
        globals.single { it.locator == fixture.locator(label) }

    private fun scan(root: Path, fixture: TypeGraphElf,
        limits: BoundedDwarfInterfaceFactLimits = BoundedDwarfInterfaceFactLimits()): BoundedDwarfInterfaceFacts {
        val path = writeElf(root.resolve("global-facts.elf"), fixture.bytes)
        return StableControlFile.open(path, fixture.bytes.size.toLong(), "global DWARF fixture").use { artifact ->
            BoundedDwarfInterfaceFactScanner.scan(artifact, root, limits = limits)
        }
    }

    private fun hexBytes(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it.toInt() and 0xff) }
}

/** Native compiler fixtures exercise emitted DWARF and ELF independently of any recovered model. */
class BoundedDwarfGlobalCompiledFactsTest {
    @Test
    fun `compiled globals static locals TLS and automatic variables keep their distinct source evidence`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val artifact = compileGlobalFixture(root, "globals.c", """
                volatile int exposed_counter = 3;
                static int file_counter = 5;
                int zero_counter;
                const int fixed_counter = 7;
                _Thread_local int tls_counter = 11;
                _Alignas(32) int aligned_counter = 23;
                __attribute__((visibility("hidden"))) int hidden_counter = 29;
                extern volatile int counter_alias __attribute__((alias("exposed_counter")));
                typedef struct GlobalRecord { int value; } GlobalRecord;
                GlobalRecord record_value = { 19 };
                int *counter_pointer = &zero_counter;
                __attribute__((noinline)) int touch(int input) {
                    static int local_counter = 13;
                    int stack_counter = input + local_counter;
                    {
                        volatile int block_counter = stack_counter + file_counter;
                        zero_counter += block_counter;
                    }
                    local_counter += input;
                    exposed_counter += tls_counter + fixed_counter + record_value.value;
                    aligned_counter += hidden_counter;
                    return stack_counter + *counter_pointer + counter_alias + aligned_counter;
                }
                int main(void) { return touch(1); }
            """.trimIndent())
            val facts = scanInterfaceFixture(artifact, root)
            assertContentEquals(facts.canonicalBytes(), scanInterfaceFixture(artifact, root).canonicalBytes())
            val expected = setOf("exposed_counter", "file_counter", "zero_counter", "fixed_counter", "tls_counter",
                "aligned_counter", "hidden_counter", "record_value", "counter_pointer", "local_counter",
                "stack_counter", "block_counter")
            assertTrue(facts.globals.flatMap { it.sourceName.values }.toSet().containsAll(expected))
            assertEquals(facts.globals.size, facts.globals.map { it.locator }.distinct().size)
            for (name in listOf("exposed_counter", "file_counter", "zero_counter", "fixed_counter", "aligned_counter",
                "hidden_counter", "record_value", "counter_pointer")) {
                val global = facts.globalNamed(name)
                knownGlobal(global.scope, "file")
                knownGlobal(global.storage, "static-storage")
                assertEquals(DwarfInterfaceFactState.KNOWN, global.address.state)
                val symbols = facts.objectSymbols.filter { it.name == name }
                assertTrue(symbols.isNotEmpty(), "ELF object symbol is missing for $name")
                assertEquals(setOf(global.address.values.single()), symbols.map { "0x${it.value.toString(16)}" }.toSet())
                assertEquals(setOf(global.rva.values.single()), symbols.map { "0x${requireNotNull(it.rva).toString(16)}" }.toSet())
                assertTrue(symbols.all { it.storage == FullTreeElfObjectStorage.MAPPED_LOAD })
                assertEquals(DwarfInterfaceFactState.KNOWN, global.type.state)
                assertTrue(global.type.values.all(facts.types::containsKey))
            }
            knownGlobal(facts.globalNamed("exposed_counter").external, "1")
            assertEquals(DwarfInterfaceFactState.ABSENT, facts.globalNamed("file_counter").external.state)
            assertEquals(DwarfInterfaceFactState.ABSENT, facts.globalNamed("exposed_counter").constant.state)
            assertEquals(DwarfInterfaceFactState.ABSENT, facts.globalNamed("exposed_counter").byteSize.state)
            knownGlobal(facts.globalNamed("aligned_counter").alignment, "32")
            val fixedType = facts.types.getValue(facts.globalNamed("fixed_counter").type.values.single())
            assertEquals(0x26L, fixedType.tag)
            val recordType = facts.types.getValue(facts.globalNamed("record_value").type.values.single())
            assertEquals(0x16L, recordType.tag)
            assertEquals(listOf("GlobalRecord"), recordType.name.values)
            assertEquals(listOf("value"), facts.types.getValue(recordType.type.values.single()).children.map { it.name.values.single() })
            val localStatic = facts.globalNamed("local_counter")
            knownGlobal(localStatic.scope, "function")
            knownGlobal(localStatic.storage, "static-storage")
            assertEquals(DwarfInterfaceFactState.KNOWN, localStatic.address.state)
            for ((name, scope) in listOf("stack_counter" to "function", "block_counter" to "block")) {
                val automatic = facts.globalNamed(name)
                knownGlobal(automatic.scope, scope)
                knownGlobal(automatic.storage, "automatic")
                assertEquals(DwarfInterfaceFactState.UNKNOWN, automatic.address.state)
                assertTrue(automatic.address.values.isEmpty())
                assertTrue(automatic.rva.values.isEmpty())
                assertTrue(automatic.location.values.single().kind in setOf("frame-relative", "register"))
            }
            val tls = facts.globalNamed("tls_counter")
            knownGlobal(tls.scope, "file")
            knownGlobal(tls.storage, "thread-local")
            assertEquals(DwarfInterfaceFactState.UNKNOWN, tls.address.state)
            assertTrue(tls.address.values.isEmpty())
            assertTrue(tls.rva.values.isEmpty())
            assertEquals(DwarfInterfaceFactState.KNOWN, tls.tlsOffset.state)
            val tlsSymbols = facts.objectSymbols.filter { it.name == "tls_counter" }
            assertTrue(tlsSymbols.isNotEmpty())
            assertTrue(tlsSymbols.all { it.type == 6 && it.storage == FullTreeElfObjectStorage.TLS && it.rva == null })
            assertEquals(tls.tlsOffset.values.toSet(), tlsSymbols.map { "0x${it.value.toString(16)}" }.toSet())
            val bss = facts.objectSymbols.filter { it.name == "zero_counter" }
            assertTrue(bss.all { it.sectionType == 8L && it.size == 4UL }) // SHT_NOBITS, C int.
            assertTrue(facts.objectSymbols.filter { it.name == "file_counter" }.all { it.binding == 0 })
            assertTrue(facts.objectSymbols.filter { it.name == "hidden_counter" }.all { it.visibility == 2 })
            val original = facts.objectSymbols.filter { it.name == "exposed_counter" }
            val aliases = facts.objectSymbols.filter { it.name == "counter_alias" }
            assertTrue(aliases.isNotEmpty())
            assertEquals(original.map { it.value }.toSet(), aliases.map { it.value }.toSet())
            assertTrue(aliases.none { alias -> original.any { it.locator == alias.locator } })
        }

    @Test
    fun `compiled out of line class and namespace definitions retain declaration ancestry`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val artifact = compileGlobalFixture(root, "global-scopes.cpp", """
                namespace State {
                    int namespace_value = 31;
                    struct Holder { static int member_value; };
                    int Holder::member_value = 37;
                }
                int main() { return State::namespace_value + State::Holder::member_value; }
            """.trimIndent(), "c++")
            val facts = scanInterfaceFixture(artifact, root)
            val namespaceValue = facts.globals.single { "namespace_value" in it.sourceName.values && it.address.state == DwarfInterfaceFactState.KNOWN }
            knownGlobal(namespaceValue.scope, "namespace")
            knownGlobal(namespaceValue.storage, "static-storage")
            assertTrue(namespaceValue.scopes.any { "State" in it.name.values })
            val members = facts.globals.filter { "member_value" in it.sourceName.values }
            assertTrue(members.size >= 2, "a static member declaration and its out-of-line definition should both remain")
            val declaration = members.single { "1" in it.declaration.values }
            val definition = members.single { it.address.state == DwarfInterfaceFactState.KNOWN }
            assertTrue(declaration.locator in definition.origins)
            knownGlobal(definition.scope, "class")
            knownGlobal(definition.storage, "static-storage")
            assertEquals(DwarfInterfaceFactState.ABSENT, definition.declaration.state)
            assertTrue(definition.scopes.any { "Holder" in it.name.values && it.ownerLocator == declaration.locator })
            assertTrue(definition.linkageName.values.single().contains("member_value"))
        }

    @Test
    fun `stripping debug data retains ELF objects without fabricating source globals`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val artifact = compileGlobalFixture(root, "stripped-globals.c", """
                int retained_global = 41;
                static int retained_static = 43;
                _Thread_local int retained_tls = 47;
                int main(void) { return retained_global + retained_static + retained_tls; }
            """.trimIndent())
            val rich = scanInterfaceFixture(artifact, root)
            assertTrue(rich.globals.isNotEmpty())
            assertTrue(rich.objectSymbols.any { it.name == "retained_global" })
            runGlobalFixtureCommand(root, listOf("strip", "--strip-debug", artifact.toString()))
            val stripped = scanInterfaceFixture(artifact, root)
            assertFalse(stripped.dwarfPresent)
            assertEquals(emptyList(), stripped.globals)
            assertEquals(emptyMap(), stripped.types)
            assertEquals(0L, stripped.scannedDies)
            val names = setOf("retained_global", "retained_static", "retained_tls")
            val before = rich.objectSymbols.filter { it.name in names }.map { listOf(it.name, it.value.toString(), it.storage.name) }.toSet()
            val after = stripped.objectSymbols.filter { it.name in names }.map { listOf(it.name, it.value.toString(), it.storage.name) }.toSet()
            assertEquals(before, after)
            assertTrue(stripped.objectSymbols.filter { it.name == "retained_tls" }.all { it.rva == null })
            runGlobalFixtureCommand(root, listOf("strip", "--strip-all", artifact.toString()))
            val fullyStripped = scanInterfaceFixture(artifact, root)
            assertFalse(fullyStripped.dwarfPresent)
            assertEquals(emptyList(), fullyStripped.globals)
            assertEquals(emptyMap(), fullyStripped.types)
        }

    @Test
    fun `ELF object ceiling is enforced independently from the raw variable ceiling`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val artifact = compileGlobalFixture(root, "object-limit.c", """
                int first_global = 1;
                int second_global = 2;
                int main(void) { return first_global + second_global; }
            """.trimIndent())
            assertTrue(scanInterfaceFixture(artifact, root).objectSymbols.size >= 2)
            assertFailsWith<FullTreeControlException> {
                scanInterfaceFixture(artifact, root, BoundedDwarfInterfaceFactLimits(maximumObjects = 1))
            }
        }

    private fun BoundedDwarfInterfaceFacts.globalNamed(name: String): DwarfGlobalVariableFacts =
        globals.single { name in it.sourceName.values }

    private fun knownGlobal(fact: DwarfInterfaceFact<String>, value: String) {
        assertEquals(DwarfInterfaceFactState.KNOWN, fact.state)
        assertEquals(listOf(value), fact.values)
    }

    private fun compileGlobalFixture(root: Path, name: String, source: String, compiler: String = "cc"): Path {
        val sourcePath = root.resolve(name)
        java.nio.file.Files.writeString(sourcePath, source)
        val artifact = root.resolve("${name.substringBeforeLast('.')}.elf")
        runGlobalFixtureCommand(root, listOf(compiler, "-O0", "-g", "-gdwarf-5", "-fno-eliminate-unused-debug-types",
            "-fno-pie", "-no-pie", sourcePath.toString(), "-o", artifact.toString()))
        return artifact
    }

    private fun runGlobalFixtureCommand(root: Path, command: List<String>) {
        val diagnostics = root.resolve("global-compiler.log")
        val process = ProcessBuilder(command).directory(root.toFile()).redirectErrorStream(true)
            .redirectOutput(diagnostics.toFile()).apply {
                environment()["TMPDIR"] = root.toString()
                environment()["TMP"] = root.toString()
                environment()["TEMP"] = root.toString()
            }.start()
        try {
            assertTrue(process.waitFor(30, java.util.concurrent.TimeUnit.SECONDS), "global fixture command exceeded its bounded runtime")
            assertEquals(0, process.exitValue(), java.nio.file.Files.readString(diagnostics).take(16_384))
        } finally {
            if (process.isAlive) process.destroyForcibly().waitFor(5, java.util.concurrent.TimeUnit.SECONDS)
        }
    }
}

class BoundedDwarfRetainedWorkingSetTest {
    @Test
    fun `sequential compilation units may exceed cumulative bytes while each operation stays bounded`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val fixture = typeElfUnits((0..3).map { index ->
                TypeGraphCompilationUnit("unit$index", listOf(
                    emitted("function$index", "int$index", index),
                    die("global$index", 0x34, listOf(text(0x03, "global$index"), reference(0x49, "int$index"))),
                    integerType("int$index"),
                ))
            })
            val path = writeElf(root.resolve("sequential-units.elf"), fixture.bytes)
            val baseline = scanInterfaceFixture(path, root,
                BoundedDwarfInterfaceFactLimits(maximumCachedCompilationUnits = 1))
            assertTrue(baseline.peakRetainedUnitBytes > 0L)
            assertTrue(baseline.loadedUnitBytes > baseline.peakRetainedUnitBytes)
            val bounded = scanInterfaceFixture(path, root, BoundedDwarfInterfaceFactLimits(
                maximumCachedCompilationUnits = 1,
                maximumRetainedWorkingSetBytes = baseline.peakRetainedUnitBytes,
            ))
            assertEquals(4, bounded.compilationUnits)
            assertEquals((0..3).map { "function$it" }.toSet(), bounded.functions.flatMap { it.sourceName.values }.toSet())
            assertEquals((0..3).map { "global$it" }.toSet(), bounded.globals.flatMap { it.sourceName.values }.toSet())
            assertEquals((0..3).map { fixture.locator("int$it") }.toSet(), bounded.types.keys)
            assertEquals(baseline.loadedUnitBytes, bounded.loadedUnitBytes)
            assertEquals(baseline.peakRetainedUnitBytes, bounded.peakRetainedUnitBytes)
            assertTrue(bounded.loadedUnitBytes > bounded.limits.maximumRetainedWorkingSetBytes)
            assertTrue(bounded.peakRetainedUnitBytes <= bounded.limits.maximumRetainedWorkingSetBytes)
        }

    @Test
    fun `cross unit references pin their complete working set and reuse evicted pinned units`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val fixture = crossUnitFixture()
            var workingSet = 0L
            withRepositoryFixture(root, fixture) { repository, headers ->
                val original = repository.load(headers[0])
                repository.withRetainedUnits(original) {
                    val declaration = follow(repository, original, fixture, "definition", 0x47)
                    val alias = follow(repository, declaration.unit, fixture, "declaration", 0x49)
                    workingSet = 2L * (original.index.modeledRetainedBytes +
                        declaration.unit.index.modeledRetainedBytes + alias.unit.index.modeledRetainedBytes)
                    assertEquals(workingSet, repository.loadedUnitBytes)
                    assertEquals(workingSet, repository.peakRetainedUnitBytes)
                    // The one-entry LRU now contains the alias CU; the original and declaration CUs
                    // must still come from the operation's pins without another physical parse.
                    kotlin.test.assertSame(original, repository.load(headers[0]))
                    kotlin.test.assertSame(declaration.unit, repository.load(headers[1]))
                    val base = follow(repository, alias.unit, fixture, "alias", 0x49)
                    kotlin.test.assertSame(original, base.unit)
                    assertEquals(fixture.offsets.getValue("base").toLong(), base.record.offset)
                    assertEquals(workingSet, repository.loadedUnitBytes)
                }
            }
            withRepositoryFixture(root, fixture, workingSet) { repository, headers ->
                val original = repository.load(headers[0])
                repository.withRetainedUnits(original) {
                    val declaration = follow(repository, original, fixture, "definition", 0x47)
                    val alias = follow(repository, declaration.unit, fixture, "declaration", 0x49)
                    kotlin.test.assertSame(original, follow(repository, alias.unit, fixture, "alias", 0x49).unit)
                    assertEquals(workingSet, repository.peakRetainedUnitBytes)
                }
                // A separate operation must not retain pins from the completed three-unit graph.
                val unrelated = repository.load(headers[3])
                repository.withRetainedUnits(unrelated) { repository.load(headers[2]); Unit }
                assertTrue(repository.loadedUnitBytes > workingSet)
                assertTrue(repository.peakRetainedUnitBytes <= workingSet)
            }
            val path = writeElf(root.resolve("cross-unit-scan.elf"), fixture.bytes)
            val facts = scanInterfaceFixture(path, root, BoundedDwarfInterfaceFactLimits(
                maximumCachedCompilationUnits = 1, maximumRetainedWorkingSetBytes = workingSet,
            ))
            assertEquals(listOf("cross_name"), facts.functions.single().sourceName.values)
            assertEquals(listOf(fixture.locator("alias")), facts.functions.single().returnType.values)
            assertEquals(listOf(fixture.locator("base")), facts.types.getValue(fixture.locator("alias")).type.values)
            assertEquals(workingSet, facts.peakRetainedUnitBytes)
        }

    @Test
    fun `cross unit pin budget rejects the next retained unit and releases pins after failure`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val fixture = crossUnitFixture()
            var workingSet = 0L
            withRepositoryFixture(root, fixture) { repository, headers ->
                val original = repository.load(headers[0])
                repository.withRetainedUnits(original) {
                    val declaration = follow(repository, original, fixture, "definition", 0x47)
                    follow(repository, declaration.unit, fixture, "declaration", 0x49)
                    workingSet = repository.peakRetainedUnitBytes
                }
            }
            withRepositoryFixture(root, fixture, workingSet - 1L) { repository, headers ->
                val original = repository.load(headers[0])
                assertFailsWith<FullTreeControlException> {
                    repository.withRetainedUnits(original) {
                        val declaration = follow(repository, original, fixture, "definition", 0x47)
                        follow(repository, declaration.unit, fixture, "declaration", 0x49)
                    }
                }
                val unrelated = repository.load(headers[3])
                repository.withRetainedUnits(unrelated) {
                    assertEquals(headers[3].offset, unrelated.header.offset)
                }
                assertTrue(repository.peakRetainedUnitBytes < workingSet)
            }
        }

    private fun crossUnitFixture(): TypeGraphElf = typeElfUnits(listOf(
        TypeGraphCompilationUnit("rootUnit", listOf(
            die("definition", 0x2e, listOf(address(0x11, 0x400100), globalReference(0x47, "declaration"))),
            integerType("base"),
        )),
        TypeGraphCompilationUnit("declarationUnit", listOf(
            die("declaration", 0x2e, listOf(text(0x03, "cross_name"), globalReference(0x49, "alias"))),
        )),
        TypeGraphCompilationUnit("typeUnit", listOf(
            die("alias", 0x16, listOf(text(0x03, "CrossInt"), globalReference(0x49, "base"))),
        )),
        TypeGraphCompilationUnit("unrelatedUnit", listOf(integerType("unrelatedBase"))),
    ))

    private fun globalReference(name: Long, target: String): TypeGraphAttribute =
        reference(name, target).copy(form = FULL_TREE_DW_FORM_REF_ADDR)

    private fun follow(repository: FunctionDwarfUnitRepository, owner: FunctionDwarfUnit,
        fixture: TypeGraphElf, label: String, name: Long): ResolvedFunctionDie {
        val record = owner.index.required(fixture.offsets.getValue(label).toLong(), label)
        return repository.resolveReference(owner, requireNotNull(record.optionalUniqueAttribute(name, label)), label)
    }

    private fun withRepositoryFixture(root: Path, fixture: TypeGraphElf, maximumBytes: Long? = null,
        block: (FunctionDwarfUnitRepository, List<FullTreeDwarfCompilationUnitHeader>) -> Unit) {
        val path = writeElf(root.resolve("retained-unit-repository.elf"), fixture.bytes)
        StableControlFile.open(path, fixture.bytes.size.toLong(), "retained-unit repository fixture").use { artifact ->
            val controls = FullTreeControlLimits()
            FullTreeDwarfSections.open(artifact, root, controls).use { sections ->
                val parseBudget = FullTreeDwarfParseBudget(controls.maximumDwarfParseSteps)
                val iterator = FullTreeDwarfCompilationUnitHeaders(sections.required(".debug_info"),
                    controls.maximumCompilationUnits.toLong(), parseBudget)
                val headers = ArrayList<FullTreeDwarfCompilationUnitHeader>()
                while (iterator.hasNext()) headers += iterator.next()
                val repository = FunctionDwarfUnitRepository(sections, headers, controls,
                    FullTreeFunctionObservationProducerLimits(maximumCachedCompilationUnits = 1), parseBudget,
                    retainAllRecords = true, maximumRetainedWorkingSetBytes = maximumBytes)
                block(repository, headers)
            }
        }
    }
}
