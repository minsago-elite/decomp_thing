package decompengine.oracle.fulltree

import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class BoundedDwarfInterfaceFactsTest {
    @Test
    fun `GNU alternate references remain external and common inclusion is a known physical tag`(): Unit =
        inInterfaceFixtureDirectory { root ->
            fun fixture(indirectOperand: Long) = typeElf(
                die("declaration", DW_TAG_SUBPROGRAM, listOf(flag(DW_AT_DECLARATION)), children = listOf(
                    die("inclusion", 0x1b, listOf(reference(0x1a, "block"))))),
                die("block", 0x1a),
                die("vendor", 0x4080, listOf(
                    TypeGraphAttribute(0x49, FULL_TREE_DW_FORM_GNU_REF_ALT, ByteArray(4), "block"),
                    raw(0x47, FULL_TREE_DW_FORM_INDIRECT, uleb(FULL_TREE_DW_FORM_GNU_REF_ALT) + fixed(indirectOperand, 4)),
                    number(0x3f, 1))),
            )
            val baseline = fixture(0)
            val fixture = fixture(baseline.offsets.getValue("block").toLong())
            val artifact = writeElf(root.resolve("alternate-common.elf"), fixture.bytes)
            val facts = scanInterfaceFixture(artifact, root)
            val vendor = facts.physicalDies.single { it.locator == fixture.locator("vendor") }
            assertEquals("unknown", vendor.category)
            assertEquals(listOf(FULL_TREE_DW_FORM_GNU_REF_ALT, FULL_TREE_DW_FORM_INDIRECT), vendor.references.map { it.declaredForm })
            assertEquals(listOf(0, 1), vendor.references.map { it.indirectDepth })
            for (ref in vendor.references) {
                assertEquals(FULL_TREE_DW_FORM_GNU_REF_ALT, ref.resolvedForm)
                assertEquals(fixture.offsets.getValue("block").toULong(), ref.rawOperand)
                assertEquals(null, ref.targetLocator)
                assertEquals("unsupported-reference", ref.state)
                assertEquals(listOf("unsupported-reference"), ref.reasons)
            }
            val inclusion = facts.physicalDies.single { it.locator == fixture.locator("inclusion") }
            assertEquals("other-known", inclusion.category)
            assertEquals(fixture.locator("declaration"), inclusion.parentLocator)
            assertEquals(fixture.locator("block"), inclusion.references.single().targetLocator)
            StableControlFile.open(artifact, Files.size(artifact), "alternate reference replay").use {
                BoundedDwarfInterfaceFactScanner.verifyPhysicalCensus(it, root, facts)
            }
            val inventory = BoundedDwarfObservationInventoryV1.collect(facts, emptyList(), null, inputs = listOf(
                BoundedDwarfObservationInput("rich", facts.inputSha256, facts.inputBytes)))
            val verifier = BoundedDwarfObservationInventoryV1.authenticatedVerifier(inventory.manifest, facts)
            verifier.acceptStrippedLayout(null)
            facts.visitCanonicalShards(verifier::accept)
            BoundedDwarfCanonicalShardWriter(consumer = verifier::accept).apply { write("strippedObjects", emptySequence()); finish() }
            inventory.visitCanonicalShards(verifier::accept)
            verifier.finish()
        }

    @Test
    fun `source replay target lookups share the aggregate parse work budget`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val declarations = (0 until 32).map { index ->
                die("node$index", 0x16, listOf(reference(0x49, if (index == 31) "int" else "node${index + 1}")))
            }
            val fixture = typeElf(*(declarations + integerType()).toTypedArray())
            val artifact = writeElf(root.resolve("lookup-budget.elf"), fixture.bytes)
            val facts = scanInterfaceFixture(artifact, root)
            StableControlFile.open(artifact, Files.size(artifact), "bounded lookup source replay").use { input ->
                BoundedDwarfInterfaceFactScanner.verifyPhysicalCensus(input, root, facts)
                val failure = assertFailsWith<FullTreeControlException> {
                    BoundedDwarfInterfaceFactScanner.verifyPhysicalCensus(input, root, facts,
                        FullTreeControlLimits(maximumDwarfParseSteps = 512))
                }
                assertTrue(failure.message.orEmpty().contains("aggregate parse-step bound"), failure.message)
                assertTrue(failure.message.orEmpty().contains("physical replay target lookup"), failure.message)
            }
        }

    @Test
    fun `physical census retains declarations unreachable types locals vendor tags and raw unresolved edges`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val fixture = typeElf(
                emitted("entry", "reachable").copy(children = listOf(
                    die("scope", 0x0b, children = listOf(die("local", 0x34, listOf(text(DW_AT_NAME, "local"),
                        reference(0x49, "unreachable-b"), raw(0x02, FULL_TREE_DW_FORM_EXPRLOC,
                            uleb(1) + byteArrayOf(0x50)))))))),
                die("declaration", DW_TAG_SUBPROGRAM, listOf(flag(DW_AT_DECLARATION), reference(0x49, "unreachable-a"))),
                integerType("reachable"),
                die("unreachable-a", 0x13, listOf(text(DW_AT_NAME, "Same"), reference(0x49, "unreachable-b")),
                    children = listOf(die("member", 0x0d, listOf(reference(0x49, "unreachable-a"))))),
                die("unreachable-b", 0x13, listOf(text(DW_AT_NAME, "Same"), reference(0x49, "unreachable-a"))),
                die("vendor", 0x4080, listOf(reference(0x49, "reachable", addend = 1),
                    raw(0x31, FULL_TREE_DW_FORM_REF_SIG8, ByteArray(8)),
                    raw(0x47, FULL_TREE_DW_FORM_REF4, ByteArray(4) { 0x7f }))),
            )
            val artifact = writeElf(root.resolve("physical-universe.elf"), fixture.bytes)
            val facts = scanInterfaceFixture(artifact, root, BoundedDwarfInterfaceFactLimits(typeGraphScope = BoundedDwarfTypeGraphScope.ABI_LAYOUT))
            assertTrue(facts.physicalCensusPresent)
            assertEquals(setOf(fixture.locator("entry")), facts.functions.map { it.locator }.toSet())
            assertEquals(setOf(fixture.locator("reachable")), facts.types.keys)
            val local = facts.globals.single { it.locator == fixture.locator("local") }
            assertEquals(DwarfInterfaceFactState.KNOWN, local.storage.state)
            assertEquals(listOf("automatic"), local.storage.values)
            assertEquals(listOf(fixture.locator("unreachable-b")), local.type.values)
            assertTrue("type-graph-not-expanded-for-automatic-local" in local.type.reasons)
            val census = facts.physicalDies.associateBy { it.locator }
            assertEquals(10, census.size)
            assertEquals("function", census.getValue(fixture.locator("declaration")).category)
            assertEquals("type", census.getValue(fixture.locator("unreachable-a")).category)
            assertEquals("type", census.getValue(fixture.locator("unreachable-b")).category)
            assertEquals("variable", census.getValue(fixture.locator("local")).category)
            assertEquals(fixture.locator("scope"), census.getValue(fixture.locator("local")).parentLocator)
            val vendor = census.getValue(fixture.locator("vendor"))
            assertEquals("unknown", vendor.category)
            assertEquals(listOf("missing-target", "unsupported-reference", "out-of-range-reference"), vendor.references.map { it.state })
            assertTrue(vendor.references.first().targetLocator != null, "interior target retains its raw physical locator")
            assertTrue(facts.physicalDies.flatMap { it.references }.any { "reference-cycle" in it.reasons })
            val unit = facts.physicalUnits.single()
            assertEquals(census.size.toLong(), unit.nonNullRecordCount)
            assertEquals(4L, unit.nullRecordCount)
            assertEquals(unit.nonNullRecordCount + unit.nullRecordCount, facts.scannedDies)
            val repeated = scanInterfaceFixture(artifact, root, facts.limits)
            assertContentEquals(facts.canonicalBytes(), repeated.canonicalBytes())
            StableControlFile.open(artifact, Files.size(artifact), "physical replay fixture").use { input ->
                BoundedDwarfInterfaceFactScanner.verifyPhysicalCensus(input, root, facts)
                fun changed(dies: List<DwarfPhysicalDieCensus>, units: List<DwarfPhysicalUnitCensus> = facts.physicalUnits) =
                    BoundedDwarfInterfaceFacts(facts.inputSha256, facts.inputBytes, facts.elfType, facts.imageBase,
                        facts.executableRanges, facts.functions, facts.types, facts.scannedDies, facts.compilationUnits,
                        facts.dwarfPresent, facts.limits, physicalUnits = units, physicalDies = dies, physicalCensusPresent = true)
                assertFailsWith<Exception> { BoundedDwarfInterfaceFactScanner.verifyPhysicalCensus(input, root, changed(facts.physicalDies.dropLast(1))) }
                assertFailsWith<Exception> { BoundedDwarfInterfaceFactScanner.verifyPhysicalCensus(input, root, changed(facts.physicalDies + facts.physicalDies.last())) }
                val altered = facts.physicalDies.map { if (it.locator == fixture.locator("vendor"))
                    DwarfPhysicalDieCensus(it.compilationUnitOffset, it.offset, it.endOffset, 0x34, it.depth, it.parentOffset,
                        it.hasChildren, it.references) else it }
                assertFailsWith<Exception> { BoundedDwarfInterfaceFactScanner.verifyPhysicalCensus(input, root, changed(altered)) }
                val realDeclaration = census.getValue(fixture.locator("declaration"))
                val realReference = realDeclaration.references.single()
                val forgedReference = DwarfPhysicalReferenceCensus(realReference.attributeOrdinal, realReference.attribute,
                    realReference.declaredForm, realReference.resolvedForm, realReference.indirectDepth, realReference.rawOperand,
                    realReference.targetLocator, "missing-target").also { it.bindTargets(census.keys) }
                val forgedState = facts.physicalDies.map { if (it.locator == realDeclaration.locator)
                    DwarfPhysicalDieCensus(it.compilationUnitOffset, it.offset, it.endOffset, it.tag, it.depth, it.parentOffset,
                        it.hasChildren, listOf(forgedReference)) else it }
                assertFailsWith<IllegalArgumentException> {
                    BoundedDwarfInterfaceFactScanner.verifyPhysicalCensus(input, root, changed(forgedState))
                }
                val forgedCycleReference = DwarfPhysicalReferenceCensus(realReference.attributeOrdinal, realReference.attribute,
                    realReference.declaredForm, realReference.resolvedForm, realReference.indirectDepth, realReference.rawOperand,
                    realReference.targetLocator).also { it.bindTargets(census.keys); it.markCycle() }
                val forgedCycle = facts.physicalDies.map { if (it.locator == realDeclaration.locator)
                    DwarfPhysicalDieCensus(it.compilationUnitOffset, it.offset, it.endOffset, it.tag, it.depth, it.parentOffset,
                        it.hasChildren, listOf(forgedCycleReference)) else it }
                assertFailsWith<IllegalArgumentException> {
                    BoundedDwarfInterfaceFactScanner.verifyPhysicalCensus(input, root, changed(forgedCycle))
                }
            }
        }

    @Test
    fun `physical census keeps cross unit references and exact separate unit counts`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val fixture = typeElfUnits(listOf(
                TypeGraphCompilationUnit("one", listOf(die("declaration", DW_TAG_SUBPROGRAM,
                    listOf(TypeGraphAttribute(0x49, FULL_TREE_DW_FORM_REF_ADDR, ByteArray(4), "other-type"))))),
                TypeGraphCompilationUnit("two", listOf(integerType("other-type"))),
            ))
            val artifact = writeElf(root.resolve("physical-units.elf"), fixture.bytes)
            val facts = scanInterfaceFixture(artifact, root)
            assertEquals(2, facts.physicalUnits.size)
            assertEquals(4, facts.physicalDies.size)
            assertEquals(facts.scannedDies, facts.physicalUnits.sumOf { it.physicalRecordCount })
            assertEquals(2L, facts.physicalUnits.sumOf { it.nullRecordCount })
            val reference = facts.physicalDies.single { it.locator == fixture.locator("declaration") }.references.single()
            assertEquals(fixture.locator("other-type"), reference.targetLocator)
            assertEquals("retained-target", reference.state)
            assertFailsWith<IllegalStateException> { reference.markCycle() }
            assertFailsWith<IllegalStateException> { reference.bindTargets(setOf(fixture.locator("other-type"))) }
            assertFailsWith<UnsupportedOperationException> {
                @Suppress("UNCHECKED_CAST")
                (facts.physicalDies as MutableList<DwarfPhysicalDieCensus>).clear()
            }
        }

    @Test
    fun `converging function origins charge the retained name once without losing provenance`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val longName = "F".repeat(4096)
            val branches = (0 until 15).map { index ->
                fun target(child: Int) = if (child < 15) "branch$child" else "leaf"
                die("branch$index", DW_TAG_SUBPROGRAM, listOfNotNull(
                    address(DW_AT_LOW_PC, 0x400100).takeIf { index == 0 },
                    reference(0x31, target(index * 2 + 1)),
                    reference(0x47, target(index * 2 + 2)),
                ))
            }
            val fixture = typeElf(*(branches + die("leaf", DW_TAG_SUBPROGRAM,
                listOf(text(DW_AT_NAME, longName)))).toTypedArray())
            val artifact = writeElf(root.resolve("function-origin-diamond.elf"), fixture.bytes)
            val generous = scanInterfaceFixture(artifact, root)
            val bounded = scanInterfaceFixture(artifact, root, BoundedDwarfInterfaceFactLimits(
                maximumOutputBytes = 128 * 1024, maximumRetainedFactBytes = 128 * 1024,
            ))
            val function = bounded.functions.single()
            assertEquals(fixture.locator("branch0"), function.locator)
            assertEquals(DwarfInterfaceFactState.KNOWN, function.sourceName.state)
            assertEquals(listOf(longName), function.sourceName.values)
            assertEquals(listOf("${fixture.locator("leaf")}:attribute=0x3"), function.sourceName.evidence)
            assertEquals((branches.map { fixture.locator(it.label) } + fixture.locator("leaf")).toSet(),
                function.origins.toSet())
            assertEquals(16, function.origins.size)
            assertEquals(generous.toJson() - "limits", bounded.toJson() - "limits")
        }

    @Test
    fun `compiled scalar pointer typedef aggregate and variadic interfaces preserve independent rich facts`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val artifact = compileInterfaceFixture(root, "interfaces.c", """
                #include <stdarg.h>
                typedef unsigned long Counter;
                struct Link { Counter value; struct Link *next; };
                Counter scalar(Counter count, int step) { return count + step; }
                const struct Link *pointer(const struct Link *head) { return head; }
                struct Link aggregate(Counter value) { struct Link item = { value, 0 }; return item; }
                double variadic(int count, ...) {
                    va_list args; va_start(args, count);
                    double result = count ? va_arg(args, double) : 0.0;
                    va_end(args); return result;
                }
                void no_return(void) {}
                int main(void) { no_return(); return (int)scalar(aggregate(1).value, 2); }
            """.trimIndent())
            val facts = scanInterfaceFixture(artifact, root)
            val repeated = scanInterfaceFixture(artifact, root)
            assertContentEquals(facts.canonicalBytes(), repeated.canonicalBytes())
            assertTrue(facts.dwarfPresent)
            assertTrue(facts.scannedDies > facts.functions.size)
            assertEquals(Files.size(artifact), facts.inputBytes)
            assertTrue(facts.functions.all { it.rva != null && it.executable })
            val scalar = facts.functionNamed("scalar")
            assertEquals(listOf("count", "step"), scalar.parameters.map { it.name.values.single() })
            assertEquals(listOf(0, 1), scalar.parameters.map { it.ordinal })
            assertEquals(DwarfInterfaceFactState.KNOWN, scalar.returnType.state)
            val counter = facts.types.getValue(scalar.returnType.values.single())
            assertEquals(0x16L, counter.tag) // DW_TAG_typedef, retained rather than flattened.
            assertEquals(listOf("Counter"), counter.name.values)
            assertEquals(listOf("7"), facts.types.getValue(counter.type.values.single()).encoding.values)
            assertEquals(DwarfInterfaceFactState.ABSENT, scalar.callingConvention.state)
            assertTrue(scalar.language.values.single().toLong() > 0)
            val pointer = facts.functionNamed("pointer")
            assertEquals(0x0fL, facts.types.getValue(pointer.returnType.values.single()).tag)
            val aggregate = facts.functionNamed("aggregate")
            val structure = facts.types.getValue(aggregate.returnType.values.single())
            assertEquals(0x13L, structure.tag)
            assertEquals(listOf("value", "next"), structure.children.map { it.name.values.single() })
            assertTrue(facts.types.values.any { node ->
                node.type.reasons.any { it.startsWith("type-reference-cycle:") }
            })
            val variadic = facts.functionNamed("variadic")
            assertEquals(listOf(true), variadic.variadic.values)
            assertEquals(listOf("count"), variadic.parameters.map { it.name.values.single() })
            assertEquals(DwarfInterfaceFactState.ABSENT, facts.functionNamed("no_return").returnType.state)
            assertEquals(emptyList(), facts.functionNamed("no_return").parameters)
            assertFailsWith<UnsupportedOperationException> {
                @Suppress("UNCHECKED_CAST")
                (facts.functions as MutableList<DwarfInterfaceFunctionFacts>).clear()
            }
            assertFailsWith<UnsupportedOperationException> {
                @Suppress("UNCHECKED_CAST")
                (structure.children as MutableList<DwarfInterfaceTypeChild>).clear()
            }
        }

    @Test
    fun `compiled C++ specification links retain return parameters linkage and source language`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val artifact = compileInterfaceFixture(root, "declarations.cpp", """
                typedef unsigned long Counter;
                struct Calculator { Counter calculate(Counter amount) const; };
                Counter Calculator::calculate(Counter amount) const { return amount + 2; }
                int main() { Calculator calculator; return calculator.calculate(3); }
            """.trimIndent(), compiler = "c++")
            val facts = scanInterfaceFixture(artifact, root)
            val method = facts.functionNamed("calculate")
            assertTrue(method.origins.size >= 2, "the compiled definition should inherit its class declaration")
            assertTrue(method.linkageName.values.single().startsWith("_ZN"))
            assertEquals(DwarfInterfaceFactState.KNOWN, method.returnType.state)
            assertEquals("Counter", facts.types.getValue(method.returnType.values.single()).name.values.single())
            assertEquals(listOf("this", "amount"), method.parameters.map { it.name.values.single() })
            assertEquals(listOf("1"), method.parameters.first().artificial.values)
            // A declaration flag on the specification must not turn the emitted definition into a declaration.
            assertEquals(DwarfInterfaceFactState.ABSENT, method.declaration.state)
            assertNotNull(method.rva)
        }

    @Test
    fun `artifact identity and resource ceilings fail before interface evidence escapes`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val artifact = compileInterfaceFixture(root, "limits.c", """
                int add(int left, int right) { return left + right; }
                int main(void) { return add(1, 2); }
            """.trimIndent())
            listOf(
                BoundedDwarfInterfaceFactLimits(maximumArtifactBytes = 1),
                BoundedDwarfInterfaceFactLimits(maximumScannedDies = 1),
                BoundedDwarfInterfaceFactLimits(maximumRetainedWorkingSetBytes = 1),
                BoundedDwarfInterfaceFactLimits(maximumFunctions = 1),
                BoundedDwarfInterfaceFactLimits(maximumParameters = 1),
                BoundedDwarfInterfaceFactLimits(maximumRetainedFactBytes = 1),
                BoundedDwarfInterfaceFactLimits(maximumOutputBytes = 1, maximumRetainedFactBytes = 1024 * 1024),
            ).forEach { limits ->
                val failure = assertFailsWith<FullTreeControlException> { scanInterfaceFixture(artifact, root, limits) }
                if (limits.maximumRetainedFactBytes == 1L) {
                    assertTrue(failure.message.orEmpty().contains("retained fact bound"))
                } else if (limits.maximumOutputBytes == 1L) {
                    assertTrue(failure.message.orEmpty().contains("aggregate shard budget exceeded"))
                }
            }
            StableControlFile.open(artifact, Files.size(artifact), "mutable interface fixture").use { file ->
                assertFailsWith<FullTreeControlException> {
                    BoundedDwarfInterfaceFactScanner.scan(file, root, checkpoint = { point ->
                        if (point == "after hashing interface ELF") Files.move(artifact, root.resolve("displaced.elf"))
                    })
                }
            }
        }

    @Test
    fun `stripped input reports missing DWARF without manufacturing a source signature`(): Unit =
        inInterfaceFixtureDirectory { root ->
            val artifact = compileInterfaceFixture(root, "stripped.c", "int main(void) { return 0; }")
            runInterfaceCommand(root, listOf("strip", "--strip-debug", artifact.toString()))
            val facts = scanInterfaceFixture(artifact, root)
            assertFalse(facts.dwarfPresent)
            assertEquals(emptyList(), facts.functions)
            assertEquals(emptyMap(), facts.types)
            assertEquals(0L, facts.scannedDies)
        }
}

private fun BoundedDwarfInterfaceFacts.functionNamed(name: String): DwarfInterfaceFunctionFacts =
    functions.single { name in it.sourceName.values }

internal fun scanInterfaceFixture(
    path: Path,
    root: Path,
    limits: BoundedDwarfInterfaceFactLimits = BoundedDwarfInterfaceFactLimits(),
): BoundedDwarfInterfaceFacts = StableControlFile.open(path, Files.size(path), "compiled interface fixture").use {
    BoundedDwarfInterfaceFactScanner.scan(it, root, limits = limits)
}

private fun compileInterfaceFixture(root: Path, name: String, source: String, compiler: String = "cc"): Path {
    val sourcePath = root.resolve(name)
    Files.writeString(sourcePath, source)
    val artifact = root.resolve("${name.substringBeforeLast('.')}.elf")
    runInterfaceCommand(root, listOf(compiler, "-O0", "-g", "-gdwarf-5", "-fno-eliminate-unused-debug-types",
        "-fno-pie", "-no-pie", sourcePath.toString(), "-o", artifact.toString()))
    return artifact
}

private fun runInterfaceCommand(root: Path, command: List<String>) {
    val diagnostics = root.resolve("compiler.log")
    val process = ProcessBuilder(command).directory(root.toFile()).redirectErrorStream(true)
        .redirectOutput(diagnostics.toFile()).apply {
            environment()["TMPDIR"] = root.toString()
            environment()["TMP"] = root.toString()
            environment()["TEMP"] = root.toString()
        }.start()
    try {
        assertTrue(process.waitFor(30, TimeUnit.SECONDS), "fixture compiler exceeded its bounded runtime")
        assertEquals(0, process.exitValue(), Files.readString(diagnostics).take(16_384))
    } finally {
        if (process.isAlive) process.destroyForcibly().waitFor(5, TimeUnit.SECONDS)
    }
}

internal inline fun <T> inInterfaceFixtureDirectory(block: (Path) -> T): T {
    val parent = Path.of("build", "dwarf-interface-fixtures").toAbsolutePath()
    Files.createDirectories(parent)
    val directory = Files.createTempDirectory(parent, "case-")
    return try { block(directory) } finally {
        Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
    }
}
