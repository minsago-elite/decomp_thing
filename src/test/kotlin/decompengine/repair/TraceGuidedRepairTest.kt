package decompengine.repair

import decompengine.project.MakeProjectBuilder
import decompengine.validation.BehaviorCaseResult
import decompengine.validation.BehaviorComparator
import decompengine.validation.ProcessInput
import decompengine.validation.ProcessOutput
import com.sun.net.httpserver.HttpServer
import java.net.InetSocketAddress
import java.net.URI
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.pathString
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
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
    fun `OpenRouter repair loop can patch compile errors`() {
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
    fun `OpenRouter HTTP client parses patch responses`() {
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
                        "content": "{\"summary\":\"fix compile error\",\"patches\":[{\"relativePath\":\"src/reconstructed.c\",\"replacement\":\"int decomp_engine_main(void) {\\n    return 0;\\n}\\n\"}]}"
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
            val client = HttpOpenRouterRepairClient(
                apiKey = "test-key",
                model = "openrouter/test",
                endpoint = URI.create("http://127.0.0.1:${server.address.port}/api/v1/chat/completions"),
            )

            val response = client.requestRepair(
                RepairRequest(
                    failureKind = "compile",
                    prompt = "compiler stderr",
                    projectFiles = mapOf("src/reconstructed.c" to "broken"),
                    regressionInputs = listOf(ProcessInput(id = "default")),
                ),
            )

            assertEquals("fix compile error", response.summary)
            assertEquals("src/reconstructed.c", response.patches.single().relativePath)
            assertTrue(response.patches.single().replacement.contains("return 0;"))
            assertTrue(requests.single().contains("openrouter/test"))
            assertTrue(requests.single().contains("compiler stderr"))
        } finally {
            server.stop(0)
        }
    }

    @Test
    fun `OpenRouter repair loop can patch behavior mismatches`() {
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

    private class FakeRepairClient(private val response: RepairResponse) : OpenRouterRepairClient {
        var lastRequest: RepairRequest? = null

        override fun requestRepair(request: RepairRequest): RepairResponse {
            lastRequest = request
            return response
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
