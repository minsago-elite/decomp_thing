package decompengine.project

import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.time.Duration
import java.util.concurrent.TimeUnit
import kotlin.io.path.createDirectories
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue

/** Qualification runs the bundled Java API worker on independently inspected stripped ELF input. */
class ReferencedDataBytesRealGhidraTest {
    @Test
    fun `stripped eight byte loads preserve leading zeros and exact reference addresses`() {
        assumeTrue(System.getenv("RUN_REAL_GHIDRA") == "true", "bundled Ghidra qualification opt in")
        val root = Files.createTempDirectory(Path.of("build", "referenced-bytes-real").createDirectories(), "fixture-").toAbsolutePath()
        val source = root.resolve("fixture.s")
        val binary = root.resolve("fixture")
        source.writeText("""
            .section .rodata
            .balign 8
            .global half_value,quarter_value,eight_value
            .type half_value,@object
            half_value: .quad 0x3fe0000000000000
            .size half_value,1
            .type quarter_value,@object
            quarter_value: .quad 0x3fd0000000000000
            .size quarter_value,1
            .type eight_value,@object
            eight_value: .quad 0x4020000000000000
            .size eight_value,1
            .text
            .global probe
            .type probe,@function
            probe:
              movsd half_value(%rip), %xmm0
              movsd quarter_value(%rip), %xmm1
              movsd eight_value(%rip), %xmm2
              ret
            .size probe,.-probe
            .section .note.GNU-stack,"",@progbits
        """.trimIndent())
        command(root, "gcc", "-nostdlib", "-no-pie", "-Wl,-e,probe", source.toString(), "-o", binary.toString())
        val symbols = command(root, "readelf", "-sW", binary.toString())
        val addresses = listOf("half_value", "quarter_value", "eight_value").associateWith { name ->
            val row = symbols.lineSequence().single { it.trim().endsWith(" $name") }.trim().split(Regex("\\s+"))
            assertEquals("1", row[2], "fixture deliberately declares one-byte ELF symbols; analysis may create wider listing data")
            row[1].toULong(16)
        }
        val expected = mapOf("half_value" to "000000000000e03f", "quarter_value" to "000000000000d03f", "eight_value" to "0000000000002040")
        // Inspect ELF program headers independently of Ghidra to map VMA to actual file bytes.
        val elf = binary.readBytes()
        val b = java.nio.ByteBuffer.wrap(elf).order(java.nio.ByteOrder.LITTLE_ENDIAN)
        val phoff = b.getLong(32).toInt(); val phsize = b.getShort(54).toInt() and 65535; val phcount = b.getShort(56).toInt() and 65535
        for ((name, address) in addresses) {
            val header = (0 until phcount).map { phoff + it * phsize }.single { p ->
                b.getInt(p) == 1 && address >= b.getLong(p + 16).toULong() && address + 8UL <= (b.getLong(p + 16) + b.getLong(p + 32)).toULong()
            }
            val offset = (b.getLong(header + 8).toULong() + address - b.getLong(header + 16).toULong()).toInt()
            assertEquals(expected.getValue(name), elf.copyOfRange(offset, offset + 8).joinToString("") { "%02x".format(it) })
        }
        command(root, "strip", "--strip-all", binary.toString())
        source.toFile().delete()
        val model = GhidraHeadlessProgramModelAnalyzer(limits = GhidraProgramModelExportLimits(Duration.ofMinutes(2)))
            .analyze(binary, root.resolve("analysis"))
        assertEquals(3, model.schemaVersion)
        for ((name, address) in addresses) {
            val windows = model.globals.flatMap { it.byteEvidence!!.windows }.filter { it.address == address && it.requestedLength == 8 }
            assertTrue(windows.isNotEmpty(), "missing eight-byte access for $name at $address")
            windows.forEach { window ->
                assertEquals("pcode_direct_read", window.origin.widthBasis)
                assertEquals(address, window.origin.referenceAddress)
                assertEquals("available", window.availability)
                assertEquals(expected.getValue(name), window.segments.joinToString("") { it.hex!! })
            }
        }
        val planning = GhidraHeadlessProgramModelAnalyzer(
            limits = GhidraProgramModelExportLimits(Duration.ofMinutes(2)),
            recoveryMode = GhidraProgramModelRecoveryMode.PLANNING).analyze(binary, root.resolve("planning-analysis"))
        assertEquals(model.globals.associate { it.id to it.byteEvidence }, planning.globals.associate { it.id to it.byteEvidence },
            "planning and full exports must retain identical windows")
        val request = ModuleReconstructionRequest(
            PlannedModule("fixture", "src/fixture.c", "include/fixture.h", emptyList(), model.globals.map { it.id }, boundaryEvidence = emptyList()),
            model, "", "", "", emptyMap(), root)
        val prompt = GeneratedCModulePrompt.render(request).evidence
        model.globals.forEach { global ->
            assertTrue(prompt.contains(ReferencedDataByteEvidenceJson.render(requireNotNull(global.byteEvidence))))
        }
        val modelPath = root.resolve("analysis/reports/program_model.json")
        val digest = MessageDigest.getInstance("SHA-256").digest(binary.readBytes()).joinToString("") { "%02x".format(it) }
        root.resolve("fixture-evidence.txt").writeText("inputSha256=$digest\n" + addresses.entries.joinToString("\n") { "${it.key}=0x${it.value.toString(16)}:${expected.getValue(it.key)}" } + "\nmodelBytes=${modelPath.readBytes().size}\n")
    }

    private fun command(root: Path, vararg args: String): String {
        val process = ProcessBuilder(*args).directory(root.toFile()).redirectErrorStream(true).start()
        assertTrue(process.waitFor(30, TimeUnit.SECONDS), args.joinToString(" "))
        val output = process.inputStream.bufferedReader().readText()
        assertEquals(0, process.exitValue(), output)
        return output
    }
}
