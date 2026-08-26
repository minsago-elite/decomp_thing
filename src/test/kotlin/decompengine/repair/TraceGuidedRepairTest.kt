package decompengine.repair

import decompengine.project.MakeProjectBuilder
import decompengine.project.RecoveredFunction
import decompengine.project.RecoveredProgramModel
import decompengine.project.SourceTreeGenerator
import decompengine.validation.BehaviorCaseResult
import decompengine.validation.BehaviorComparator
import decompengine.validation.ProcessInput
import decompengine.validation.ProcessOutput
import com.sun.net.httpserver.HttpServer
import java.net.InetSocketAddress
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.pathString
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class TraceGuidedRepairTest {
    @Test
    fun `failed validation cases produce structured diffs`() {
        val result = BehaviorCaseResult(
            input = ProcessInput(id = "default"),
            original = ProcessOutput(
                exitCode = 0,
                stdout = "hello\n".toByteArray(),
                stderr = ByteArray(0),
                sandboxCommand = listOf("bwrap"),
            ),
            rebuilt = ProcessOutput(
                exitCode = 1,
                stdout = "hullo\n".toByteArray(),
                stderr = "err\n".toByteArray(),
                sandboxCommand = listOf("bwrap"),
            ),
        )

        val diff = StructuredDiffBuilder.from("hello_world", listOf(result))

        assertEquals(false, diff.matches)
        assertEquals(false, diff.cases.single().exitCodeMatches)
        assertEquals(1, diff.cases.single().stdout.firstDifferenceOffset)
        assertEquals("68656c6c6f0a", diff.cases.single().stdout.expectedHex)
        assertEquals("68756c6c6f0a", diff.cases.single().stdout.actualHex)
    }

    @Test
    fun `repair loop can patch compile errors`() {
        val tempDir = createTempDirectory("repair-compile-")
        val projectDir = createProject(tempDir.resolve("project"), reconstructedSource = "int decomp_engine_main(void) {\n")
        val history = RepairHistory(projectDir.resolve("reports/repair_history.json"))
        val client = FakeRepairClient(
            RepairResponse(
                summary = "close missing brace",
                patches = listOf(SourcePatch("src/reconstructed.c", goodHelloSource())),
            ),
        )
        val failure = collectCompileFailure(projectDir)

        val iteration = TraceGuidedRepairLoop(client, history).repairCompileError(
            projectDir = projectDir,
            failure = failure,
            regressionInputs = listOf(ProcessInput(id = "hello_default")),
        )
        val build = MakeProjectBuilder.build(projectDir)

        assertEquals("compile", iteration.failureKind)
        assertEquals(listOf("hello_default"), iteration.retainedRegressionIds)
        assertTrue(build.projectDir.resolve("build/reconstructed").exists())
        assertTrue(history.all().single().summary.contains("brace"))
        assertTrue(projectDir.resolve("reports/repair_history.json").readText().contains("hello_default"))
        assertTrue(client.lastRequest!!.prompt.contains("stderr:"))
    }

    @Test
    fun `OpenAI-compatible HTTP client uses configured base URL and parses patch responses`() {
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        val requests = mutableListOf<String>()
        server.createContext("/api/v1/chat/completions") { exchange ->
            requests += exchange.requestBody.bufferedReader().readText()
            assertEquals("Bearer test-key", exchange.requestHeaders.getFirst("Authorization"))
            val response = """
                {
                  "choices": [
                    {
                      "message": {
                        "content": "{\"summary\":\"fix \\\"quoted\\\" compile error\",\"patches\":[{\"relativePath\":\"src/reconstructed.c\",\"replacement\":\"int decomp_engine_main(void) {\\n    return 0;\\n}\\n\"}]}"
                      }
                    }
                  ]
                }
            """.trimIndent()
            exchange.sendResponseHeaders(200, response.toByteArray().size.toLong())
            exchange.responseBody.use { it.write(response.toByteArray()) }
        }
        server.start()
        try {
            val client = HttpOpenAiCompatibleRepairClient.fromEnvironment(
                mapOf(
                    "API_KEY" to "test-key",
                    "MODEL" to "compatible/test",
                    "BASE_URL" to "http://127.0.0.1:${server.address.port}/api/v1",
                    "REASONING_EFFORT" to "high",
                ),
            )

            val response = client.requestRepair(
                RepairRequest(
                    failureKind = "compile",
                    prompt = "compiler stderr",
                    projectFiles = mapOf("src/reconstructed.c" to "broken"),
                    regressionInputs = listOf(ProcessInput(id = "default")),
                ),
            )

            assertEquals("fix \"quoted\" compile error", response.summary)
            assertEquals("src/reconstructed.c", response.patches.single().relativePath)
            assertTrue(response.patches.single().replacement.contains("return 0;"))
            assertTrue(requests.single().contains("compatible/test"))
            assertTrue(requests.single().contains("\"reasoning_effort\": \"high\""))
            assertTrue(requests.single().contains("compiler stderr"))
        } finally {
            server.stop(0)
        }
    }

    @Test
    fun `OpenAI-compatible client rejects unsupported reasoning effort`() {
        val error = assertFailsWith<IllegalArgumentException> {
            HttpOpenAiCompatibleRepairClient.fromEnvironment(
                mapOf(
                    "API_KEY" to "test-key",
                    "MODEL" to "compatible/test",
                    "BASE_URL" to "https://api.example.com/v1",
                    "REASONING_EFFORT" to "maximum",
                ),
            )
        }

        assertTrue(error.message.orEmpty().contains("REASONING_EFFORT"))
    }

    @Test
    fun `repair loop can patch behavior mismatches`() {
        val tempDir = createTempDirectory("repair-behavior-")
        val original = compileC(tempDir, "original", helloProgramSource("hello, world"))
        val projectDir = createProject(tempDir.resolve("project"), reconstructedSource = helloMainSource("wrong"))
        val initialBuild = MakeProjectBuilder.build(projectDir)
        val history = RepairHistory(projectDir.resolve("reports/repair_history.json"))
        val client = FakeRepairClient(
            RepairResponse(
                summary = "match observed stdout",
                patches = listOf(SourcePatch("src/reconstructed.c", goodHelloSource())),
            ),
        )
        val inputs = listOf(ProcessInput(id = "hello_default"))

        val iteration = TraceGuidedRepairLoop(client, history).repairBehaviorMismatch(
            projectDir = projectDir,
            originalBinary = original,
            rebuiltBinary = initialBuild.projectDir.resolve("build/reconstructed"),
            inputs = inputs,
            reportsDir = projectDir.resolve("reports"),
        )
        val repairedBuild = MakeProjectBuilder.build(projectDir)
        val repairedReport = BehaviorComparator().compare(
            id = "hello_world_after_repair",
            originalBinary = original,
            rebuiltBinary = repairedBuild.projectDir.resolve("build/reconstructed"),
            cases = inputs,
            reportsDir = projectDir.resolve("reports"),
        )

        assertEquals("behavior", iteration.failureKind)
        assertTrue(client.lastRequest!!.prompt.contains("Structured behavior diff"))
        assertTrue(repairedReport.matches)
        assertEquals(listOf("hello_default"), history.all().single().retainedRegressionIds)
    }

    @Test
    fun `regression tests are retained across repair attempts`() {
        val tempDir = createTempDirectory("repair-regression-")
        val projectDir = createProject(tempDir.resolve("project"), reconstructedSource = "int decomp_engine_main(void) {\n")
        val history = RepairHistory(projectDir.resolve("reports/repair_history.json"))
        val inputs = listOf(
            ProcessInput(id = "no_args"),
            ProcessInput(id = "two_args", args = listOf("alpha", "beta")),
        )

        TraceGuidedRepairLoop(FakeRepairClient(RepairResponse("fix", listOf(SourcePatch("src/reconstructed.c", goodHelloSource())))), history)
            .repairCompileError(projectDir, collectCompileFailure(projectDir), inputs)

        assertEquals(listOf("no_args", "two_args"), history.all().single().retainedRegressionIds)
        val historyJson = projectDir.resolve("reports/repair_history.json").readText()
        assertTrue(historyJson.contains("no_args"))
        assertTrue(historyJson.contains("two_args"))
    }

    @Test
    fun `repair loop iterates from compile failure through behavior mismatch and persists regressions`() {
        val tempDir = createTempDirectory("repair-converge-")
        val original = compileC(tempDir, "original", helloProgramSource("hello, world"))
        val projectDir = createProject(tempDir.resolve("project"), reconstructedSource = "int decomp_engine_main(void) {\n")
        val historyPath = projectDir.resolve("reports/repair_history.json")
        val inputs = listOf(
            ProcessInput(id = "default"),
            ProcessInput(id = "argument", args = listOf("kept")),
        )
        val client = QueueRepairClient(
            RepairResponse("make it compile", listOf(SourcePatch("src/reconstructed.c", helloMainSource("wrong")))),
            RepairResponse("match observed output", listOf(SourcePatch("src/reconstructed.c", goodHelloSource()))),
        )

        val result = TraceGuidedRepairLoop(client, RepairHistory(historyPath)).repairUntilValid(
            projectDir = projectDir,
            originalBinary = original,
            inputs = inputs,
            maxIterations = 3,
        )

        assertTrue(result.validation.matches)
        assertEquals(listOf("compile", "behavior"), result.iterations.map { it.failureKind })
        assertEquals(false, result.iterations.first().succeeded)
        assertEquals(true, result.iterations.last().succeeded)
        assertEquals("compile", result.iterations.first().before?.kind)
        assertEquals("behavior", result.iterations.first().after?.kind)
        assertEquals("valid", result.iterations.last().after?.kind)
        assertEquals(inputs.map { it.id }, client.requests.last().regressionInputs.map { it.id })
        assertTrue(projectDir.resolve("reports/iteration_1_behavior.diff.json").exists())

        val reloaded = RepairHistory(historyPath)
        assertEquals(inputs, reloaded.retainedInputs())
        assertEquals(2, reloaded.all().size)
        assertTrue(historyPath.readText().contains("\"before\""))
        assertTrue(historyPath.readText().contains("\"after\""))
    }

    @Test
    fun `reloaded repair history retains earlier regressions in later requests`() {
        val tempDir = createTempDirectory("repair-reload-")
        val projectDir = createProject(tempDir.resolve("project"), reconstructedSource = "int decomp_engine_main(void) {\n")
        val historyPath = projectDir.resolve("reports/repair_history.json")
        RepairHistory(historyPath).retain(listOf(ProcessInput("earlier", stdin = "old\n".toByteArray())))
        val client = QueueRepairClient(RepairResponse("fix", listOf(SourcePatch("src/reconstructed.c", goodHelloSource()))))

        TraceGuidedRepairLoop(client, RepairHistory(historyPath)).repairCompileError(
            projectDir,
            collectCompileFailure(projectDir),
            listOf(ProcessInput("new", args = listOf("value"))),
        )

        assertEquals(listOf("earlier", "new"), client.requests.single().regressionInputs.map { it.id })
    }

    @Test
    fun `repair discovers manifest-owned modules and sends compile-relevant context`() {
        val tempDir = createTempDirectory("repair-tree-")
        val projectDir = tempDir.resolve("project")
        SourceTreeGenerator.generate(multiModuleModel(), projectDir)
        val parsePath = projectDir.resolve("src/modules/parse.c")
        val validParse = parsePath.readText()
        parsePath.writeText("#include \"modules/parse.h\"\nint parse_input(void) {\n")
        val client = FakeRepairClient(RepairResponse("repair parse module", listOf(SourcePatch("src/modules/parse.c", validParse))))

        TraceGuidedRepairLoop(client, RepairHistory(projectDir.resolve("reports/repair_history.json"))).repairCompileError(
            projectDir,
            collectCompileFailure(projectDir),
            listOf(ProcessInput("default")),
        )

        assertEquals(0, MakeProjectBuilder.build(projectDir).returnCode)
        assertTrue("src/modules/parse.c" in client.lastRequest!!.projectFiles)
        assertTrue("include/modules/parse.h" in client.lastRequest!!.projectFiles)
        assertTrue("src/modules/render.c" !in client.lastRequest!!.projectFiles)
        assertTrue(projectDir.resolve("reports/source_revisions.jsonl").readText().contains("src/modules/parse.c"))
    }

    @Test
    fun `manifest restriction rejects an invalid multi-file response before any write`() {
        val tempDir = createTempDirectory("repair-tree-atomic-")
        val projectDir = tempDir.resolve("project")
        SourceTreeGenerator.generate(multiModuleModel(), projectDir)
        val parsePath = projectDir.resolve("src/modules/parse.c")
        parsePath.writeText("broken\n")
        val before = parsePath.readText()
        val client = FakeRepairClient(
            RepairResponse(
                "unsafe response",
                listOf(SourcePatch("src/modules/parse.c", "replacement\n"), SourcePatch("src/rogue.c", "rogue\n")),
            ),
        )

        assertFailsWith<IllegalArgumentException> {
            TraceGuidedRepairLoop(client, RepairHistory(projectDir.resolve("reports/repair_history.json"))).repairCompileError(
                projectDir,
                CompileFailure(listOf("make"), 2, "", "src/modules/parse.c: error"),
                emptyList(),
            )
        }

        assertEquals(before, parsePath.readText())
        assertTrue(!projectDir.resolve("src/rogue.c").exists())
    }

    @Test
    fun `compile-breaking behavior repair rolls back to the last buildable tree`() {
        val tempDir = createTempDirectory("repair-rollback-")
        val original = compileC(tempDir, "original", helloProgramSource("hello, world"))
        val projectDir = createProject(tempDir.resolve("project"), reconstructedSource = helloMainSource("wrong"))
        MakeProjectBuilder.build(projectDir)
        val before = projectDir.resolve("src/reconstructed.c").readText()
        val client = QueueRepairClient(RepairResponse("bad repair", listOf(SourcePatch("src/reconstructed.c", "int broken(\n"))))

        assertFailsWith<RepairExhaustedException> {
            TraceGuidedRepairLoop(client, RepairHistory(projectDir.resolve("reports/repair_history.json"))).repairUntilValid(
                projectDir,
                original,
                listOf(ProcessInput("default")),
                maxIterations = 1,
            )
        }

        assertEquals(before, projectDir.resolve("src/reconstructed.c").readText())
        assertEquals(0, MakeProjectBuilder.build(projectDir).returnCode)
        assertTrue(projectDir.resolve("reports/source_revisions.jsonl").readText().contains("\"accepted\":false"))
    }

    private class FakeRepairClient(private val response: RepairResponse) : RepairClient {
        var lastRequest: RepairRequest? = null

        override fun requestRepair(request: RepairRequest): RepairResponse {
            lastRequest = request
            return response
        }
    }

    private class QueueRepairClient(vararg responses: RepairResponse) : RepairClient {
        private val responses = ArrayDeque(responses.toList())
        val requests = mutableListOf<RepairRequest>()

        override fun requestRepair(request: RepairRequest): RepairResponse {
            requests += request
            return responses.removeFirstOrNull() ?: error("unexpected repair request")
        }
    }

    private fun createProject(projectDir: java.nio.file.Path, reconstructedSource: String): java.nio.file.Path {
        projectDir.resolve("src").createDirectories()
        projectDir.resolve("include").createDirectories()
        projectDir.resolve("reports").createDirectories()
        projectDir.resolve("Makefile").writeText(
            """
            CC ?= gcc
            CFLAGS ?= -std=c11 -Wall -Wextra -Werror -Iinclude
            TARGET ?= build/reconstructed
            SOURCES := src/main.c src/reconstructed.c

            all: ${'$'}(TARGET)

            ${'$'}(TARGET): ${'$'}(SOURCES) include/decomp_engine.h
            	@mkdir -p ${'$'}(dir ${'$'}@)
            	${'$'}(CC) ${'$'}(CFLAGS) ${'$'}(SOURCES) -o ${'$'}@
            """.trimIndent() + "\n",
        )
        projectDir.resolve("include/decomp_engine.h").writeText(
            """
            #ifndef DECOMP_ENGINE_H
            #define DECOMP_ENGINE_H

            int decomp_engine_main(void);

            #endif
            """.trimIndent() + "\n",
        )
        projectDir.resolve("src/main.c").writeText(
            """
            #include "decomp_engine.h"

            int main(void) {
                return decomp_engine_main();
            }
            """.trimIndent() + "\n",
        )
        projectDir.resolve("src/reconstructed.c").writeText(reconstructedSource)
        return projectDir
    }

    private fun multiModuleModel() = RecoveredProgramModel(
        inputSha256 = "repair-fixture",
        functions = listOf(
            RecoveredFunction("fn_1000", "parse_input", 0x1000UL, "int parse_input(void)"),
            RecoveredFunction("fn_2000", "render_page", 0x2000UL, "int render_page(void)"),
        ),
    )

    private fun collectCompileFailure(projectDir: java.nio.file.Path): CompileFailure {
        val process = ProcessBuilder("make")
            .directory(projectDir.toFile())
            .redirectErrorStream(false)
            .start()
        val stdout = process.inputStream.bufferedReader().readText()
        val stderr = process.errorStream.bufferedReader().readText()
        val exitCode = process.waitFor()
        assertTrue(exitCode != 0)
        return CompileFailure(listOf("make"), exitCode, stdout, stderr)
    }

    private fun compileC(tempDir: java.nio.file.Path, name: String, source: String): java.nio.file.Path {
        val buildDir = tempDir.resolve(name).createDirectories()
        val sourcePath = buildDir.resolve("$name.c")
        val binaryPath = buildDir.resolve(name)
        sourcePath.writeText(source)
        val process = ProcessBuilder("gcc", sourcePath.pathString, "-o", binaryPath.pathString)
            .redirectErrorStream(true)
            .start()
        val output = process.inputStream.bufferedReader().readText()
        val exitCode = process.waitFor()
        check(exitCode == 0) { "gcc failed: $output" }
        return binaryPath
    }

    private fun helloProgramSource(message: String): String = """
        #include <stdio.h>

        int main(void) {
            puts("$message");
            return 0;
        }
    """.trimIndent() + "\n"

    private fun helloMainSource(message: String): String = """
        #include <stdio.h>

        int decomp_engine_main(void) {
            puts("$message");
            return 0;
        }
    """.trimIndent() + "\n"

    private fun goodHelloSource(): String = helloMainSource("hello, world")
}
