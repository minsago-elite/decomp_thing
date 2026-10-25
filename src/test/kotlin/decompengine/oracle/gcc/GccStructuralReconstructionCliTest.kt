package decompengine.oracle.gcc

import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.analysis.AnalysisDeadline
import decompengine.analysis.GhidraAnalysisException
import decompengine.oracle.core.OracleJson
import decompengine.project.ReconstructionAdapters
import decompengine.project.RecoveredFunction
import decompengine.project.RecoveredGlobal
import decompengine.project.RecoveredProgramModel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.CancellationException
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.test.assertSame
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

    @Test
    fun `large immutable snapshot performs two full invocation validations with cheap model checkpoints`() {
        fixture { _, arguments ->
            val options = GccStructuralReconstructionOptions.parse(arguments)
            GccStructuralReconstructionInvocation.create(options, arguments).use { invocation ->
                val model = snapshotModel(1_024)
                val bytes = model.toJson().toByteArray()
                val publication = GccBundledFullExportPublication(Path.of("unused-result.json"), bytes, null)
                var validations = 0
                var checkpoints = 0
                val snapshot = snapshotStructuralAnalysis(publication, snapshotDeadline(), {
                    validations++
                    invocation.requireCurrent()
                }) { checkpoints++ }
                assertEquals(2, validations)
                assertTrue(checkpoints > 50_000, "the composition must exercise per-token and per-entity checks")
                assertContentEquals(bytes, snapshot.canonicalModelBytes)
                assertEquals(model, snapshot.model)
                assertEquals(null, snapshot.selectedStructuralInputs, "authored transport cannot acquire admission")
                assertFalse(Files.exists(options.analysisOptions.output.resolve("result.json")))
            }
        }
    }

    @Test
    fun `invocation replacement or closure during construction refuses the complete snapshot at the final guard`() {
        for (change in listOf("directory", "record", "close")) fixture { root, arguments ->
            val options = GccStructuralReconstructionOptions.parse(arguments)
            GccStructuralReconstructionInvocation.create(options, arguments).use { invocation ->
                val publication = snapshotPublication()
                var validations = 0
                var changed = false
                var constructed = false
                assertFails("$change must prevent snapshot return") {
                    snapshotStructuralAnalysis(publication, snapshotDeadline(), {
                        validations++
                        invocation.requireCurrent()
                    }) { stage ->
                        if (!changed && stage == "after reading program model function") {
                            changed = true
                            when (change) {
                                "directory" -> {
                                    Files.move(root.resolve("analysis"), root.resolve("old-analysis"))
                                    privateDirectory(root.resolve("analysis"))
                                }
                                "record" -> {
                                    val path = root.resolve("reconstruction-invocation.json")
                                    Files.move(path, root.resolve("old-invocation.json"))
                                    Files.write(path, invocation.canonicalBytes)
                                }
                                "close" -> invocation.close()
                            }
                        }
                        if (stage == "after analysis snapshot") constructed = true
                    }
                }
                assertTrue(changed, "$change did not reach the mutation point")
                assertTrue(constructed, "full revalidation must follow complete immutable construction")
                assertEquals(2, validations, "per-item checkpoints must not reauthenticate invocation files")
            }
        }
    }

    @Test
    fun `snapshot interruption and cancellation stop construction without reaching final validation`() {
        for (interrupt in listOf(false, true)) fixture { _, arguments ->
            val options = GccStructuralReconstructionOptions.parse(arguments)
            GccStructuralReconstructionInvocation.create(options, arguments).use { invocation ->
                var validations = 0
                val cancellation = CancellationException("controlled snapshot cancellation")
                try {
                    val failure = assertFails {
                        snapshotStructuralAnalysis(snapshotPublication(), snapshotDeadline(), {
                            validations++
                            invocation.requireCurrent()
                        }) { stage ->
                            if (stage == "after reading program model function") {
                                if (interrupt) Thread.currentThread().interrupt() else throw cancellation
                            }
                        }
                    }
                    if (interrupt) assertTrue(failure is InterruptedException) else assertSame(cancellation, failure)
                    assertEquals(1, validations)
                } finally {
                    Thread.interrupted()
                }
            }
        }
    }

    @Test
    fun `snapshot budget includes both full invocation validations without renewal`() {
        for (expireAt in listOf(1, 2)) fixture { _, arguments ->
            val options = GccStructuralReconstructionOptions.parse(arguments)
            GccStructuralReconstructionInvocation.create(options, arguments).use { invocation ->
                val deadline = AnalysisDeadline.start(TimeUnit.SECONDS.toNanos(5), "controlled snapshot budget")
                var validations = 0
                var completedValidations = 0
                var modelCheckpoints = 0
                val failure = assertFailsWith<GhidraAnalysisException> {
                    snapshotStructuralAnalysis(snapshotPublication(), deadline, {
                        validations++
                        invocation.requireCurrent()
                        if (validations == expireAt) {
                            // Expire inside the real boundary validation wrapper, without changing any limit.
                            while (true) {
                                val remaining = deadline.remainingNanosOrZero()
                                if (remaining == 0L) break
                                TimeUnit.NANOSECONDS.sleep(remaining)
                            }
                        }
                        completedValidations++
                    }) { modelCheckpoints++ }
                }
                assertEquals(expireAt, validations)
                assertEquals(expireAt, completedValidations)
                assertEquals(5_000L, deadline.maximumMillis)
                assertTrue(failure.message.orEmpty().contains(if (expireAt == 1)
                    "after owned snapshot invocation validation" else "after owned snapshot final invocation validation"))
                if (expireAt == 1) assertEquals(0, modelCheckpoints) else assertTrue(modelCheckpoints > 0)
            }
        }
    }

    private fun snapshotDeadline(): AnalysisDeadline =
        AnalysisDeadline.start(TimeUnit.MINUTES.toNanos(10), "component snapshot")

    private fun snapshotPublication(): GccBundledFullExportPublication =
        GccBundledFullExportPublication(Path.of("unused-result.json"), snapshotModel(1).toJson().toByteArray(), null)

    private fun snapshotModel(count: Int) = RecoveredProgramModel(4, "a".repeat(64),
        functions = List(count) { index -> RecoveredFunction("function-$index", "function_$index",
            index.toULong(), "int function_$index(void)", calls = setOf("callee-$index"),
            strings = setOf("retained string $index"), referencedGlobals = setOf("global-$index")) },
        globals = List(count) { index -> RecoveredGlobal("global-$index", "global_$index",
            (count + index).toULong(), "int") })

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
