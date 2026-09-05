package decompengine.integration

import decompengine.project.ArchivalBundleVerifier
import decompengine.project.ArchivalPackager
import decompengine.project.ArchivalProjectAuditor
import decompengine.project.DeterministicModulePlanner
import decompengine.project.MakeProjectBuilder
import decompengine.project.RecoveredFunction
import decompengine.project.RecoveredCModuleReconstructor
import decompengine.project.RecoveredGlobal
import decompengine.project.RecoveredProgramModel
import decompengine.project.RecoveredType
import decompengine.project.RecoveryStatus
import decompengine.project.SourceTreeGenerator
import decompengine.project.sha256
import decompengine.binary.ElfMetadataReader
import decompengine.validation.BehaviorComparator
import decompengine.validation.BehaviorProjectContext
import decompengine.validation.ProcessInput
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.nio.file.Path
import kotlin.io.path.Path
import kotlin.io.path.copyTo
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.isExecutable
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ArchivalProjectScaleIntegrationTest {
    private val corpus = Path("benchmarks/archival")

    @Test
    fun `versioned corpus authenticates and compiles small large PIE and stripped variants`() {
        val manifest = Json.parseToJsonElement(corpus.resolve("manifest.json").readText()).jsonObject
        assertEquals("CC0-1.0", manifest["redistribution"]!!.jsonPrimitive.content)
        val fixtures = manifest["fixtures"]!!.jsonArray.map { it.jsonObject }
        assertEquals(setOf("small_cli", "large_project"), fixtures.map { it["id"]!!.jsonPrimitive.content }.toSet())
        val temp = createTempDirectory("archival-corpus-")
        fixtures.forEach { fixture ->
            val id = fixture["id"]!!.jsonPrimitive.content
            val source = corpus.resolve(fixture["source"]!!.jsonPrimitive.content)
            assertEquals(fixture["sourceSha256"]!!.jsonPrimitive.content, sha256(source.readBytes()))
            fixture["binaries"]!!.jsonArray.map { it.jsonObject }.forEach { binaryEntry ->
                val binary = corpus.resolve(binaryEntry["path"]!!.jsonPrimitive.content)
                assertEquals(binaryEntry["sha256"]!!.jsonPrimitive.content, sha256(binary.readBytes()))
                val metadata = ElfMetadataReader.read(binary.readBytes())
                assertEquals("ELF64", metadata.format)
                assertEquals("x86-64", metadata.machine)
                val symbols = command(listOf("nm", binary.toString())).second
                if (binaryEntry["symbols"]!!.jsonPrimitive.content == "present") assertTrue(symbols.contains(" main"))
                else assertFalse(symbols.contains(" main"))
            }
            val nonPie = compile(source, temp.resolve("$id-nonpie"), listOf("-O0", "-no-pie"))
            val pie = compile(source, temp.resolve("$id-pie"), listOf("-O2", "-fPIE", "-pie"))
            assertTrue(nonPie.isExecutable() && pie.isExecutable())
            if (id == "large_project") {
                val symbolsBefore = command(listOf("nm", pie.toString())).second
                assertTrue(symbolsBefore.contains("parse_0"))
                check(command(listOf("strip", "--strip-all", pie.toString())).first == 0)
                val symbolsAfter = command(listOf("nm", pie.toString())).second
                assertFalse(symbolsAfter.contains("parse_0"))
                assertTrue(fixture["inputSurfaces"]!!.jsonArray.map { it.jsonPrimitive.content }.containsAll(listOf("argv", "stdin", "file", "libc", "shared-global-state")))
            }
        }
    }

    @Test
    fun `small reconstructed project preserves argv behavior and rebuilds from archive`() {
        val temp = createTempDirectory("archival-small-")
        val source = corpus.resolve("small_cli.c")
        val original = compile(source, temp.resolve("original"), listOf("-O0", "-no-pie"))
        val model = RecoveredProgramModel(
            inputSha256 = sha256(original.readBytes()),
            functions = listOf(
                RecoveredFunction(
                    "fn_1000", "main", 0x1000UL, "int main(int argc, char **argv)",
                    decompiledC = source.readText(),
                ),
            ),
        )
        val project = temp.resolve("project")
        SourceTreeGenerator.generate(model, project, reconstructor = RecoveredCModuleReconstructor())
        val rebuilt = MakeProjectBuilder.build(project).projectDir.resolve("build/reconstructed")

        val report = BehaviorComparator().compare(
            "small_archival",
            original,
            rebuilt,
            listOf(ProcessInput("default"), ProcessInput("one_arg", listOf("hello")), ProcessInput("exit_two", listOf("a", "b"))),
            project.resolve("reports"),
            BehaviorProjectContext(project),
        )
        val bundle = ArchivalPackager.create(project, temp.resolve("small.zip"))
        val extracted = temp.resolve("extracted")
        ArchivalBundleVerifier.extractAndVerify(bundle.archivePath, extracted)

        assertTrue(report.matches)
        assertEquals(0, MakeProjectBuilder.build(extracted).returnCode)
    }

    @Test
    fun `large recovered program splits builds validates and archives with complete provenance`() {
        val temp = createTempDirectory("archival-large-")
        val model = largeModel()
        val originalSource = temp.resolve("large.c").also { it.writeText(renderOriginal(model)) }
        val original = compile(originalSource, temp.resolve("original"), listOf("-O2", "-fPIE", "-pie"))
        check(command(listOf("strip", "--strip-all", original.toString())).first == 0)
        val project = temp.resolve("project")
        SourceTreeGenerator.generate(
            model.copy(inputSha256 = sha256(original.readBytes())),
            project,
            reconstructor = RecoveredCModuleReconstructor(),
        )
        val rebuilt = MakeProjectBuilder.build(project).projectDir.resolve("build/reconstructed")
        val fileInput = temp.resolve("sample.txt").also { it.writeText("from-file\n") }
        val inputs = listOf(
            ProcessInput("stdin", stdin = "from-stdin\n".toByteArray()),
            ProcessInput("argv", args = listOf("from-argv")),
            ProcessInput("file", args = listOf("--file", "/inputs/sample.txt")),
            ProcessInput("exit", args = listOf("a", "b", "c")),
        )
        val behavior = BehaviorComparator().compare(
            "large_archival", original, rebuilt, inputs, project.resolve("reports"), BehaviorProjectContext(project),
            fileInputs = mapOf("file" to mapOf("sample.txt" to fileInput)),
        )
        val fileCase = behavior.cases.single { it.input.id == "file" }
        assertEquals(0, fileCase.original.exitCode)
        assertEquals(0, fileCase.rebuilt.exitCode)
        assertEquals("from-file:25\n", fileCase.original.stdout.decodeToString())
        assertEquals("from-file:25\n", fileCase.rebuilt.stdout.decodeToString())
        val retainedCase = Json.parseToJsonElement(behavior.reportPath.readText()).jsonObject.getValue("cases").jsonArray
            .single { it.jsonObject.getValue("id").jsonPrimitive.content == "file" }.jsonObject
        val retainedFile = retainedCase.getValue("fileInputs").jsonArray.single().jsonObject
        assertEquals(sha256(fileInput.readBytes()), retainedFile.getValue("sha256").jsonPrimitive.content)
        assertEquals("66726f6d2d66696c650a", retainedFile.getValue("contentHex").jsonPrimitive.content)
        val first = ArchivalPackager.create(project, temp.resolve("large-1.zip"))
        val second = ArchivalPackager.create(project, temp.resolve("large-2.zip"))
        java.nio.file.Files.delete(fileInput)
        val extracted = temp.resolve("extracted")
        ArchivalBundleVerifier.extractAndVerify(first.archivePath, extracted)
        val plan = DeterministicModulePlanner().plan(model)

        assertTrue(model.functions.size > 100)
        assertTrue(plan.modules.size >= 9)
        assertTrue(behavior.matches)
        assertTrue(behavior.reportPath.readText().contains("\"sandbox\": \"bubblewrap\""))
        assertTrue(behavior.reportPath.readText().contains("\"networkIsolated\""))
        assertEquals(first.archiveSha256, second.archiveSha256)
        assertEquals(0, MakeProjectBuilder.build(extracted).returnCode)
        val extractedRecord = Json.parseToJsonElement(extracted.resolve("reports/large_archival.behavior.json").readText()).jsonObject
        val extractedFile = extractedRecord.getValue("cases").jsonArray
            .single { it.jsonObject.getValue("id").jsonPrimitive.content == "file" }.jsonObject
            .getValue("fileInputs").jsonArray.single().jsonObject
        assertEquals(retainedFile, extractedFile)
        val restoredInput = temp.resolve("restored-input.txt")
        java.nio.file.Files.write(restoredInput, java.util.HexFormat.of().parseHex(extractedFile.getValue("contentHex").jsonPrimitive.content))
        val replay = BehaviorComparator().compare(
            "large_archival_replay", original, extracted.resolve("build/reconstructed"), inputs,
            extracted.resolve("reports"), BehaviorProjectContext(extracted),
            fileInputs = mapOf("file" to mapOf("sample.txt" to restoredInput)),
        )
        val replayRecord = Json.parseToJsonElement(replay.reportPath.readText()).jsonObject
        assertEquals(extractedRecord.getValue("corpusSha256"), replayRecord.getValue("corpusSha256"))
        val expectedCases = mapOf(
            "stdin" to (0 to "from-stdin:25\n"),
            "argv" to (0 to "from-argv:25\n"),
            "file" to (0 to "from-file:25\n"),
            "exit" to (3 to "a:25\n"),
        )
        for (comparison in listOf(behavior, replay)) {
            comparison.cases.forEach { case ->
                val (exit, stdout) = expectedCases.getValue(case.input.id)
                for (output in listOf(case.original, case.rebuilt)) {
                    assertEquals(exit, output.exitCode, case.input.id)
                    assertEquals(stdout, output.stdout.decodeToString(), case.input.id)
                    assertTrue(output.stderr.isEmpty(), case.input.id)
                }
            }
        }
        val programModel = project.resolve("reports/program_model.json").readText()
        val modulePlan = project.resolve("reports/module_plan.json").readText()
        val sourceManifest = project.resolve("source_tree_manifest.json").readText()
        model.functions.forEach { function ->
            assertTrue(programModel.contains(function.id), "program model missing ${function.id}")
            assertTrue(modulePlan.contains(function.id), "module plan missing ${function.id}")
            assertTrue(sourceManifest.contains(function.id), "source manifest missing ${function.id}")
        }
        assertTrue(project.resolve("reports/confidence.json").readText().contains("opaque_context"))
        assertTrue(sourceManifest.contains("opaque_context"))
        val audit = ArchivalProjectAuditor.audit(project)
        assertTrue(audit.provenanceComplete)
        assertEquals(true, audit.behaviorMatched)
        assertTrue(audit.sandboxReported)
        assertFalse(audit.universalEquivalenceClaim)
        assertEquals(listOf("opaque_context"), audit.unresolvedEntityIds)
    }

    private fun largeModel(): RecoveredProgramModel {
        val groups = listOf("parse", "render", "store", "util")
        val helpers = groups.flatMapIndexed { groupIndex, group ->
            (0 until 30).map { index ->
                val address = 0x2000UL + (groupIndex * 0x100 + index).toULong()
                RecoveredFunction(
                    id = "fn_${address.toString(16)}",
                    name = "${group}_$index",
                    address = address,
                    prototype = "int ${group}_$index(void)",
                    decompiledC = "int ${group}_$index(void) { return $index; }",
                )
            }
        }
        val called = groups.mapIndexed { groupIndex, _ -> helpers[groupIndex * 30 + (groupIndex + 3)].id }.toSet()
        val main = RecoveredFunction(
            id = "fn_1000",
            name = "main",
            address = 0x1000UL,
            prototype = "int main(int argc, char **argv)",
            decompiledC = mainSource(),
            calls = called,
            referencedGlobals = setOf("global_5000"),
            strings = setOf("--file", "default", "%s:%d\\n"),
        )
        return RecoveredProgramModel(
            inputSha256 = "pending-binary-hash",
            functions = listOf(main) + helpers,
            globals = listOf(RecoveredGlobal("global_5000", "archive_bias", 0x5000UL, "int", "7")),
            types = listOf(RecoveredType("opaque_context", "typedef struct opaque_context opaque_context;", 0x6000UL, RecoveryStatus.PARTIAL)),
        )
    }

    private fun mainSource(): String = """
        #include <stdio.h>
        #include <string.h>
        int main(int argc, char **argv) {
            char value[128] = {0};
            if (argc >= 3 && strcmp(argv[1], "--file") == 0) {
                FILE *input = fopen(argv[2], "r");
                if (input == NULL || fgets(value, sizeof(value), input) == NULL) return 4;
                fclose(input);
            } else if (argc > 1) {
                snprintf(value, sizeof(value), "%s", argv[1]);
            } else if (fgets(value, sizeof(value), stdin) == NULL) {
                strcpy(value, "default");
            }
            value[strcspn(value, "\r\n")] = '\0';
            printf("%s:%d\n", value, archive_bias + parse_3() + render_4() + store_5() + util_6());
            return argc > 3 ? 3 : 0;
        }
    """.trimIndent()

    private fun renderOriginal(model: RecoveredProgramModel): String = buildString {
        append("#include <stdio.h>\n#include <string.h>\n\nint archive_bias = 7;\n\n")
        model.functions.filter { it.name != "main" }.forEach { append(it.decompiledC).append("\n") }
        append('\n').append(model.functions.single { it.name == "main" }.decompiledC)
    }

    private fun compile(source: Path, output: Path, flags: List<String>): Path {
        output.parent.createDirectories()
        val (exit, text) = command(listOf("gcc") + flags + listOf(source.toString(), "-o", output.toString()))
        check(exit == 0) { "gcc failed: $text" }
        check(output.exists() && output.isExecutable())
        return output
    }

    private fun command(command: List<String>): Pair<Int, String> {
        val process = ProcessBuilder(command).redirectErrorStream(true).start()
        val output = process.inputStream.bufferedReader().readText()
        return process.waitFor() to output
    }
}
