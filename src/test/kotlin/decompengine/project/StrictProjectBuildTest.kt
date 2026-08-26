package decompengine.project

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.listDirectoryEntries
import kotlin.io.path.readText
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
        assertTrue(project.resolve("reports/build_contract.json").readText().contains("\"warningsAsErrors\": true"))
        assertTrue(project.resolve("reports/build_contract.json").readText().contains("\"apiCredentialsRequired\": false"))
        assertTrue(report.logPath.readText().contains("--output-sync=target"))
        assertTrue(report.diagnosticsDir.listDirectoryEntries("*.log").isNotEmpty())
        assertTrue(report.diagnosticsDir.listDirectoryEntries("*.log").all { it.readText().contains("owner=") })

        val bundle = ArchivalPackager.create(project, project.parent.resolve("strict-build.zip"))
        assertTrue(bundle.payloadFiles.any { it.startsWith("reports/build/modules/") })
        assertTrue(project.resolve("ARCHIVE_README.md").readText().contains("command in `BUILDING.md`"))
        val extracted = project.parent.resolve("extracted")
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

    private fun buildableModel() = RecoveredProgramModel(
        inputSha256 = "strict-build-fixture",
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
