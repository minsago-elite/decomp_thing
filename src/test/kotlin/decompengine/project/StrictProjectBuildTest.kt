package decompengine.project

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.nio.file.Files
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.listDirectoryEntries
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class StrictProjectBuildTest {
    @Test
    fun `project builds once in parallel under warnings-as-errors with owned diagnostics`() {
        val project = createTempDirectory("strict-project-build-")
        SourceTreeGenerator.generate(buildableModel(), project)

        val report = MakeProjectBuilder.build(project)

        assertEquals(0, report.returnCode)
        assertEquals("--jobs=4", report.command[1])
        assertTrue(report.command.single { it.startsWith("CFLAGS=") }.contains("-Werror"))
        assertTrue(project.resolve("BUILDING.md").readText().contains(report.command.joinToString(" ").substringBefore("CFLAGS=")))
        assertTrue(project.resolve("BUILDING.md").readText().contains("does not require analysis caches"))
        val contract = Json.parseToJsonElement(project.resolve("reports/build_contract.json").readText()).jsonObject
        assertEquals(2, contract.getValue("schemaVersion").jsonPrimitive.content.toInt())
        assertEquals("true", contract.getValue("warningsAsErrors").jsonPrimitive.content)
        assertEquals("true", contract.getValue("reproduciblePathMapping").jsonPrimitive.content)
        assertEquals("false", contract.getValue("apiCredentialsRequired").jsonPrimitive.content)
        assertEquals("true", contract.getValue("sourceStableDuringBuild").jsonPrimitive.content)
        assertTrue(contract.getValue("sourceRevisionSha256").jsonPrimitive.content.matches(Regex("[a-f0-9]{64}")))
        assertTrue(contract.getValue("sourceInputs").jsonArray.any {
            it.jsonObject.getValue("path").jsonPrimitive.content == "Makefile"
        })
        val artifact = contract.getValue("artifact").jsonObject
        assertEquals("build/reconstructed", artifact.getValue("path").jsonPrimitive.content)
        assertTrue(artifact.getValue("sha256").jsonPrimitive.content.matches(Regex("[a-f0-9]{64}")))
        assertTrue(report.logPath.readText().contains("--output-sync=target"))
        assertTrue(report.diagnosticsDir.listDirectoryEntries("*.log").isNotEmpty())
        assertTrue(report.diagnosticsDir.listDirectoryEntries("*.log").all { it.readText().contains("owner=") })

        val bundle = ArchivalPackager.create(project, project.parent.resolve("strict-build.zip"))
        assertTrue(bundle.payloadFiles.any { it.startsWith("reports/build/modules/") })
        assertTrue(project.resolve("ARCHIVE_README.md").readText().contains("command in `BUILDING.md`"))
        val extracted = project.resolveSibling("${project.fileName}-extracted")
        ArchivalBundleVerifier.extractAndVerify(bundle.archivePath, extracted)
        assertTrue(extracted.resolve("BUILDING.md").exists())
        assertEquals(0, MakeProjectBuilder.build(extracted).returnCode)
    }

    @Test
    fun `warning failure is archived against the module that owns the source`() {
        val project = createTempDirectory("strict-project-failure-")
        val model = RecoveredProgramModel(
            inputSha256 = "strict-warning-fixture",
            functions = listOf(
                RecoveredFunction(
                    id = "fn_0000000000001000",
                    name = "parse_request",
                    address = 0x1000UL,
                    prototype = "int parse_request(void)",
                    decompiledC = "int parse_request(void) { int unused; return 0; }",
                ),
            ),
        )
        SourceTreeGenerator.generate(model, project, reconstructor = RecoveredCModuleReconstructor())
        val moduleId = Json.parseToJsonElement(project.resolve("reports/module_plan.json").readText())
            .jsonObject.getValue("modules").jsonArray.single().jsonObject.getValue("id").jsonPrimitive.content

        val failure = assertFailsWith<BuildException> { MakeProjectBuilder.build(project) }

        assertTrue(failure.message.orEmpty().contains("owners=$moduleId"), failure.message)
        val diagnostic = project.resolve("reports/build/modules/${safeIdentifier(moduleId)}.log")
        assertTrue(diagnostic.exists())
        assertTrue(diagnostic.readText().contains("status=failed"))
        assertTrue(diagnostic.readText().contains("unused variable"))
        val contract = project.resolve("reports/build_contract.json").readText()
        assertTrue(contract.contains("\"failedOwners\": [\"$moduleId\"]"))
        val returnCode = Json.parseToJsonElement(contract).jsonObject.getValue("returnCode").jsonPrimitive.content.toInt()
        assertTrue(returnCode != 0)
    }

    @Test
    fun `recovered named parameters are explicit no-op uses under the effective strict command`() {
        val project = createTempDirectory("strict-recovered-parameters-")
        val model = RecoveredProgramModel(
            inputSha256 = "strict-recovered-parameters",
            functions = listOf(
                RecoveredFunction(
                    id = "fn_main",
                    name = "main",
                    address = 0x1000UL,
                    prototype = "int main(int argc, char **argv)",
                    decompiledC = "int main(int argc, char **argv) { return 0; }",
                ),
            ),
        )
        SourceTreeGenerator.generate(model, project, reconstructor = RecoveredCModuleReconstructor())

        val report = MakeProjectBuilder.build(project)

        assertEquals(0, report.returnCode)
        assertTrue(report.command.single { it.startsWith("CFLAGS=") }.contains("-Werror"))
        assertTrue(project.resolve("Makefile").readText().contains("-Werror"))
        val source = project.resolve("src/modules/main.c").readText()
        assertTrue(source.contains("(void)argc;"), source)
        assertTrue(source.contains("(void)argv;"), source)
    }

    @Test
    fun `evidence stubs use named parameters and pass the effective strict command`() {
        val project = createTempDirectory("strict-evidence-parameters-")
        SourceTreeGenerator.generate(
            RecoveredProgramModel(
                inputSha256 = "strict-evidence-parameters",
                functions = listOf(
                    RecoveredFunction(
                        id = "fn_main",
                        name = "main",
                        address = 0x1000UL,
                        prototype = "int main(int argc, char **argv)",
                    ),
                ),
            ),
            project,
            reconstructor = EvidenceModuleReconstructor(),
        )

        val report = MakeProjectBuilder.build(project)

        assertEquals(0, report.returnCode)
        assertTrue(report.command.single { it.startsWith("CFLAGS=") }.contains("-Werror"))
        val source = project.resolve("src/modules/main.c").readText()
        assertTrue(source.contains("(void)argc;"), source)
        assertTrue(source.contains("(void)argv;"), source)
    }

    @Test
    fun `link failure is attributed to the module whose object references the missing symbol`() {
        val project = createTempDirectory("strict-link-failure-")
        val model = RecoveredProgramModel(
            inputSha256 = "strict-link-fixture",
            functions = listOf(
                RecoveredFunction(
                    id = "fn_0000000000001000",
                    name = "parse_request",
                    address = 0x1000UL,
                    prototype = "int parse_request(void)",
                    decompiledC = "extern int unavailable_dependency(void);\nint parse_request(void) { return unavailable_dependency(); }",
                ),
            ),
        )
        SourceTreeGenerator.generate(model, project, reconstructor = RecoveredCModuleReconstructor())
        val moduleId = Json.parseToJsonElement(project.resolve("reports/module_plan.json").readText())
            .jsonObject.getValue("modules").jsonArray.single().jsonObject.getValue("id").jsonPrimitive.content

        val failure = assertFailsWith<BuildException> { MakeProjectBuilder.build(project) }

        assertTrue(failure.message.orEmpty().contains(moduleId), failure.message)
        val diagnostic = project.resolve("reports/build/modules/${safeIdentifier(moduleId)}.log").readText()
        assertTrue(diagnostic.contains("undefined reference"))
        assertTrue(diagnostic.contains("status=failed"))
    }

    @Test
    fun `build configuration cannot disable warnings-as-errors`() {
        val failure = assertFailsWith<IllegalArgumentException> {
            ProjectBuildConfiguration(cFlags = listOf("-std=c11", "-Wall"))
        }

        assertTrue(failure.message.orEmpty().contains("warnings-as-errors"))

        assertFailsWith<IllegalArgumentException> {
            ProjectBuildConfiguration(cFlags = listOf("-std=c11", "-Werror", "-Wno-error"))
        }
    }

    @Test
    fun `build fails closed at profile supplied time and output bounds`() {
        val timeoutProject = createTempDirectory("strict-build-timeout-")
        SourceTreeGenerator.generate(buildableModel(), timeoutProject)
        timeoutProject.resolve("Makefile").writeText("all:\n\t@sleep 30\n")

        val timeout = assertFailsWith<BuildException> {
            MakeProjectBuilder.build(
                timeoutProject,
                ProjectBuildConfiguration(wallClockTimeoutMillis = 100, terminationGraceMillis = 100),
            )
        }
        assertTrue(timeout.message.orEmpty().contains("exceeded 100 milliseconds"), timeout.message)

        val outputProject = createTempDirectory("strict-build-output-")
        SourceTreeGenerator.generate(buildableModel(), outputProject)
        outputProject.resolve("Makefile").writeText("all:\n\t@yes x | head -c 4096\n")

        val output = assertFailsWith<BuildException> {
            MakeProjectBuilder.build(outputProject, ProjectBuildConfiguration(maximumOutputBytes = 128))
        }
        assertTrue(output.message.orEmpty().contains("output exceeds 128 bytes"), output.message)
    }

    @Test
    fun `build rejects symbolic output paths before writing host files`() {
        val temp = createTempDirectory("strict-build-symlink-")
        val project = temp.resolve("project")
        SourceTreeGenerator.generate(buildableModel(), project)
        val sentinel = temp.resolve("outside-sentinel").also { it.writeText("keep") }
        Files.createSymbolicLink(project.resolve("BUILDING.md"), sentinel)

        val failure = assertFailsWith<IllegalArgumentException> { MakeProjectBuilder.build(project) }

        assertTrue(failure.message.orEmpty().contains("symbolic link"))
        assertEquals("keep", sentinel.readText())
    }

    @Test
    fun `build atomically replaces hard-linked evidence without changing host files`() {
        val temp = createTempDirectory("strict-build-hardlink-")
        val project = temp.resolve("project")
        SourceTreeGenerator.generate(buildableModel(), project)
        val sentinel = temp.resolve("outside-sentinel").also { it.writeText("keep") }
        Files.createLink(project.resolve("reports/build_contract.json"), sentinel)

        assertEquals(0, MakeProjectBuilder.build(project).returnCode)
        assertEquals("keep", sentinel.readText())
        assertTrue(project.resolve("reports/build_contract.json").readText().contains("\"returnCode\": 0"))
    }

    private fun buildableModel() = RecoveredProgramModel(
        inputSha256 = sha256("strict-build-fixture".toByteArray()),
        functions = listOf(
            RecoveredFunction(
                id = "fn_0000000000001000",
                name = "parse_request",
                address = 0x1000UL,
                prototype = "int parse_request(void)",
            ),
            RecoveredFunction(
                id = "fn_0000000000001020",
                name = "render_result",
                address = 0x1020UL,
                prototype = "int render_result(void)",
            ),
        ),
    )
}
