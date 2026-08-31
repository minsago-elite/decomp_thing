package decompengine.oracle.fulltree

import java.nio.file.Files
import java.nio.file.StandardOpenOption
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class BoundedDwarfFunctionFactsTest {
    @Test
    fun `shared scanner preserves chained aliases emitted starts and inline facts`(): Unit =
        inControlTemporaryDirectory { root ->
            val fixture = ComposedFunctionObservationElf.build()
            val artifactPath = writeElf(root.resolve("function-facts.elf"), fixture.bytes)
            StableControlFile.open(artifactPath, fixture.bytes.size.toLong(), "function-fact fixture").use { artifact ->
                val facts = BoundedDwarfFunctionFactScanner.scan(
                    artifact,
                    "rich",
                    root,
                    symbolNameSelected = { true },
                    compilationUnitSelected = { true },
                    includeInlineOnly = true,
                )
                assertEquals("ET_EXEC", facts.elfType)
                assertEquals(0x400000UL, facts.imageBase)
                assertEquals(listOf(0x180UL), facts.aliasesByRva.keys.toList())
                val emitted = facts.aliasesByRva.getValue(0x180UL).getValue("chained_target")
                assertEquals(listOf("dwarf-subprogram"), emitted.map { it.kind }.distinct())
                assertEquals(
                    "rich:.debug_info:die=${hex(fixture.emittedDieOffset)}:" +
                        "DW_AT_name@${hex(fixture.declarationDieOffset)}",
                    emitted.single().locator,
                )
                assertEquals(1, facts.inlineOnly.size)
                assertEquals(
                    listOf("chained_target"),
                    facts.inlineOnly.single().second.keys.toList(),
                )
                assertEquals(
                    "rich:.debug_info:die=${hex(fixture.nonEmittedDieOffset)}:" +
                        "DW_AT_name@${hex(fixture.declarationDieOffset)}",
                    facts.inlineOnly.single().second.getValue("chained_target").single().locator,
                )
            }
        }

    @Test
    fun `shared scanner enforces aggregate record bounds and stable pathname identity`(): Unit =
        inControlTemporaryDirectory { root ->
            val fixture = ComposedFunctionObservationElf.build()
            val artifactPath = writeElf(root.resolve("bounded-function-facts.elf"), fixture.bytes)
            StableControlFile.open(artifactPath, fixture.bytes.size.toLong(), "bounded function facts").use { artifact ->
                assertFailsWith<FullTreeControlException> {
                    BoundedDwarfFunctionFactScanner.scan(
                        artifact,
                        "rich",
                        root,
                        symbolNameSelected = { true },
                        compilationUnitSelected = { true },
                        includeInlineOnly = true,
                        limits = BoundedDwarfFunctionFactLimits(maximumFunctions = 1),
                    )
                }
            }

            StableControlFile.open(artifactPath, fixture.bytes.size.toLong(), "changing function facts").use { artifact ->
                assertFailsWith<FullTreeControlException> {
                    BoundedDwarfFunctionFactScanner.scan(
                        artifact,
                        "rich",
                        root,
                        symbolNameSelected = { true },
                        compilationUnitSelected = { true },
                        includeInlineOnly = false,
                        checkpoint = { point ->
                            if (point == "after hashing rich ELF") {
                                Files.write(
                                    artifactPath,
                                    byteArrayOf(0),
                                    StandardOpenOption.APPEND,
                                )
                            }
                        },
                    )
                }
            }
        }

    private fun hex(value: Int): String = "0x${value.toString(16)}"
}
