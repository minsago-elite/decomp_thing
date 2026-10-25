package decompengine.oracle.gcc

import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.oracle.core.OracleJson
import decompengine.project.ReconstructionAdapters
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject

/** Selection/ownership controls only; no authored invocation is a production capture. */
class GccStructuralReconstructionCliTest {
    @Test
    fun `selection fixes driver fresh recovery and evidence-only registered output profile`() {
        fixture { root, arguments ->
            for (profile in listOf("generated-c-make-v1", "generated-c-ninja-v1")) {
                val selected = GccStructuralReconstructionOptions.parse(arguments + listOf("--reconstruction-profile", profile))
                assertEquals(root, selected.output)
                assertEquals(root.resolve("analysis"), selected.analysisOptions.output)
                assertEquals(root.resolve("reconstruction"), selected.reconstructionOutput)
                assertEquals("driver", selected.analysisOptions.engineId)
                assertTrue(selected.analysisOptions.fullRecoveryExport)
                assertFalse(selected.analysisOptions.nativeCallObservations)
                assertTrue(ReconstructionAdapters.resolve(selected.reconstructionProfile).requiresUnresolvedOutput(selected.reconstructionProfile))
            }
            for (extra in listOf(listOf("--harness", "acp"), listOf("--compiler", "/usr/bin/cc"),
                listOf("--resume-after-checkpoint", "512"), listOf("--reconstruction-profile", "arbitrary"),
                listOf("--reconstruction-profile", "generated-c-make-v1", "--reconstruction-profile", "generated-c-ninja-v1"))) {
                assertFails { GccStructuralReconstructionOptions.parse(arguments + extra) }
            }
        }
    }

    @Test
    fun `nested invocation binds exact reconstruction selection while historical shape stays unchanged`() {
        fixture { _, arguments ->
            val options = GccStructuralReconstructionOptions.parse(arguments)
            GccStructuralReconstructionInvocation.create(options, arguments).use { outer ->
                val directory = options.analysisOptions.output
                val identities = linkedMapOf(directory to LinuxFilesystemSyscalls.openRoot(directory).use { it.identity })
                for (name in listOf("inputs", "journal")) {
                    privateDirectory(directory.resolve(name))
                    identities[directory.resolve(name)] = LinuxFilesystemSyscalls.openRoot(directory.resolve(name)).use { it.identity }
                }
                val fresh = GccBundledCliInvocation(options.analysisOptions, options.analysisArguments, identities, outer)
                val document = OracleJson.parseCanonical(fresh.canonicalBytes).jsonObject
                assertEquals(JsonPrimitive(2), document["schemaVersion"])
                assertEquals(OracleJson.parseCanonical(outer.canonicalBytes), document["reconstructionInvocation"])
                fresh.requireCurrent()
                val old = OracleJson.parseCanonical(GccBundledCliInvocation(options.analysisOptions,
                    options.analysisArguments, identities).canonicalBytes).jsonObject
                assertEquals(JsonPrimitive(1), old["schemaVersion"])
                assertFalse("reconstructionInvocation" in old)
                assertFailsWith<IllegalArgumentException> {
                    outer.requireAnalysisSelection(options.analysisOptions.copy(engineId = "cc1"), options.analysisArguments)
                }
                assertFailsWith<IllegalArgumentException> {
                    GccOwnedStructuralProgramModelAnalyzer(outer).analyzeWithAssessment(
                        options.analysisOptions.binary.resolveSibling("different"), options.reconstructionOutput.resolve("analysis"))
                }
                assertFalse(Files.exists(directory.resolve("result.json")), "selection checks must not execute an exporter")
            }
        }
    }

    @Test
    fun `invocation refuses nonempty public aliased or cross-selected output before execution`() {
        fixture { root, arguments ->
            val options = GccStructuralReconstructionOptions.parse(arguments)
            Files.writeString(root.resolve("unowned"), "existing")
            assertFails { GccStructuralReconstructionInvocation.create(options, arguments) }
            Files.delete(root.resolve("unowned"))
            Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwxr-xr-x"))
            assertFails { GccStructuralReconstructionInvocation.create(options, arguments) }
            Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
            assertFails { GccStructuralReconstructionInvocation.create(options,
                arguments + listOf("--reconstruction-profile", "generated-c-ninja-v1")) }
            val alias = root.resolveSibling("alias")
            Files.createSymbolicLink(alias, root)
            try {
                val aliasedArguments = arguments.map { if (it == root.toString()) alias.toString() else it }
                assertFails { GccStructuralReconstructionInvocation.create(GccStructuralReconstructionOptions.parse(aliasedArguments), aliasedArguments) }
            } finally { Files.delete(alias) }
        }
    }

    @Test
    fun `closed or replaced analysis directory cannot retain invocation selection`() {
        fixture { root, arguments ->
            val options = GccStructuralReconstructionOptions.parse(arguments)
            val outer = GccStructuralReconstructionInvocation.create(options, arguments)
            try {
                Files.move(root.resolve("analysis"), root.resolve("old-analysis"))
                privateDirectory(root.resolve("analysis"))
                assertFails { outer.requireCurrent() }
            } finally { outer.close() }
            assertFails { outer.requireCurrent() }
        }
    }

    @Test
    fun `published model transport returns defensive bytes and no implicit admission`() {
        val supplied = byteArrayOf(1, 2, 3)
        val value = GccBundledFullExportPublication(Path.of("result.json"), supplied, null)
        supplied[0] = 9
        val copy = value.canonicalProgramModelBytes
        copy[1] = 9
        assertTrue(value.canonicalProgramModelBytes.contentEquals(byteArrayOf(1, 2, 3)))
        assertEquals(null, value.selectedInputs)
    }

    private fun fixture(action: (Path, List<String>) -> Unit) {
        val parent = Path.of("build/test-scratch/structural-reconstruction-cli").toAbsolutePath().normalize()
        Files.createDirectories(parent)
        val fixture = Files.createTempDirectory(parent, "selection-")
        try {
            val root = privateDirectory(fixture.resolve("output"))
            val inputs = privateDirectory(fixture.resolve("inputs"))
            val scratch = privateDirectory(fixture.resolve("scratch"))
            action(root, listOf(inputs.resolve("driver").toString(), "--profile", inputs.resolve("profile.json").toString(),
                "--ghidra-archive", inputs.resolve("ghidra.zip").toString(), "--output", root.toString(), "--scratch", scratch.toString()))
        } finally {
            Files.walk(fixture).use { it.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
    }

    private fun privateDirectory(path: Path): Path = Files.createDirectory(path,
        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
}
