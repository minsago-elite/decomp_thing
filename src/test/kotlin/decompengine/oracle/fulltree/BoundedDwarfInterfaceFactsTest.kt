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
    fun `converging function origins charge the retained name once without losing provenance`() =
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
    fun `compiled scalar pointer typedef aggregate and variadic interfaces preserve independent rich facts`() =
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
    fun `compiled C++ specification links retain return parameters linkage and source language`() =
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
    fun `artifact identity and resource ceilings fail before interface evidence escapes`() =
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
    fun `stripped input reports missing DWARF without manufacturing a source signature`() =
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
