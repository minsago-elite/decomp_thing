package decompengine.exploration

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import decompengine.validation.ProcessInput
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.pathString
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue

class AutomaticExplorationTest {
    @Test
    fun `python angr adapter returns argv stdin and exploration diagnostics`() {
        val tempDir = createTempDirectory("exploration-angr-adapter-")
        val fakePython = tempDir.resolve("fake-python").apply {
            writeText(
                """#!/bin/sh
                printf '%s\n' '{"stats":{"argvStates":2,"stdinStates":3,"argvSteps":10,"stdinSteps":11},"candidates":[{"id":"arg","mode":"argv","argv":"secret","stdinHex":""},{"id":"stdin","mode":"stdin","argv":"","stdinHex":"6f70656e0a"}]}'
                """.trimIndent(),
            )
            toFile().setExecutable(true)
        }
        val explorer = PythonAngrExplorer(python = fakePython, timeoutSeconds = 2)

        val candidates = explorer.generate(java.nio.file.Path.of("/tmp/fake-binary"))

        assertTrue(candidates.any { it.args == listOf("secret") })
        assertTrue(candidates.any { it.stdin.decodeToString() == "open\n" })
        assertEquals(AngrDiagnostics(2, 3, 10, 11), explorer.diagnostics)
    }

    @Test
    fun `real angr symbolically discovers branching argv and stdin when configured`() {
        val python = System.getenv("ANGR_PYTHON").orEmpty()
        assumeTrue(python.isNotBlank(), "real Angr requires an explicitly configured ANGR_PYTHON")
        val evidenceRoot = java.nio.file.Path.of(
            System.getProperty("decompengine.angr.evidenceRoot", "build/test-work/exploration-angr-real"),
        ).toAbsolutePath().createDirectories()
        val tempDir = java.nio.file.Files.createTempDirectory(evidenceRoot, "fixture-")
        val binary = compileBranchingProgram(tempDir)
        val explorer = PythonAngrExplorer(
            python = java.nio.file.Path.of(python),
            timeoutSeconds = 60,
            maxSteps = 400,
            maxStates = 96,
            stdinBytes = 8,
        )

        val candidates = explorer.generate(binary)
        val diagnostics = checkNotNull(explorer.diagnostics)
        fun sha256(path: java.nio.file.Path): String = java.security.MessageDigest.getInstance("SHA-256")
            .digest(java.nio.file.Files.readAllBytes(path)).joinToString("") { "%02x".format(it) }
        evidenceRoot.resolve("discovery.json").writeText(buildJsonObject {
            put("schema", "decomp-angr-authored-fixture-v1")
            put("binarySha256", sha256(binary))
            put("fixtureSourceSha256", sha256(binary.resolveSibling("branching.c")))
            put("timeoutSeconds", 60)
            put("maxSteps", 400)
            put("maxStates", 96)
            put("argvBytes", 16)
            put("stdinBytes", 8)
            put("argvStates", diagnostics.argvStates)
            put("stdinStates", diagnostics.stdinStates)
            put("argvSteps", diagnostics.argvSteps)
            put("stdinSteps", diagnostics.stdinSteps)
            put("candidates", JsonArray(candidates.map { candidate ->
                buildJsonObject {
                    put("id", candidate.id)
                    put("args", JsonArray(candidate.args.map(::JsonPrimitive)))
                    put("stdinHex", candidate.stdin.joinToString("") { "%02x".format(it) })
                }
            }))
        }.toString() + "\n")

        assertTrue(candidates.any { it.args == listOf("secret") }, candidates.toString())
        assertTrue(candidates.any { it.stdin.decodeToString().startsWith("open\n") }, candidates.toString())
        assertTrue(explorer.diagnostics!!.argvStates > 1)
        assertTrue(explorer.diagnostics!!.stdinStates > 1)
    }

    @Test
    fun `angr explorer creates candidate argv and stdin cases through adapter boundary`() {
        val candidates = FakeAngrExplorer().generate(java.nio.file.Path.of("/tmp/fake"))

        assertTrue(candidates.any { it.source == CandidateSource.ANGR && it.args == listOf("secret") })
        assertTrue(candidates.any { it.source == CandidateSource.ANGR && it.stdin.contentEquals("open\n".toByteArray()) })
    }

    @Test
    fun `string static-hint input generation works`() {
        val tempDir = createTempDirectory("exploration-static-")
        val binary = compileBranchingProgram(tempDir)

        val candidates = StaticHintGenerator().generate(binary)

        assertTrue(candidates.any { it.args.contains("secret") })
        assertTrue(candidates.any { it.stdin.decodeToString() == "open\n" })
    }

    @Test
    fun `mutation-based expansion works`() {
        val seeds = listOf(CandidateInput("seed", CandidateSource.SEED, args = listOf("Secret"), stdin = "Open\n".toByteArray()))

        val expanded = MutationExpander().expand(seeds)

        assertTrue(expanded.any { it.source == CandidateSource.MUTATION && it.args == listOf("SECRET") })
        assertTrue(expanded.any { it.stdin.decodeToString() == "open\n" })
        assertTrue(expanded.any { it.args == listOf("SecretSecret") })
        assertTrue(expanded.any { it.args.singleOrNull()?.length == 64 })
    }

    @Test
    fun `mutation deduplication preserves no arguments and one empty argument`() {
        val seed = CandidateInput("empty_arg", CandidateSource.SEED, args = listOf(""), stdin = "\n".toByteArray())
        val expanded = MutationExpander().expand(listOf(seed, seed.copy(id = "same_content")))

        assertTrue(expanded.any { it.args.isEmpty() && it.stdin.isEmpty() })
        assertTrue(expanded.any { it.args == listOf("") && it.stdin.isEmpty() })
        assertEquals(1, expanded.count { it.args == listOf("") && it.stdin.isEmpty() })
    }

    @Test
    fun `generated tests increase path and output coverage`() {
        val tempDir = createTempDirectory("exploration-coverage-")
        val binary = compileBranchingProgram(tempDir)
        val baseline = listOf(CandidateInput("empty", CandidateSource.SEED))
        val expanded = baseline + listOf(
            CandidateInput("secret_arg", CandidateSource.STATIC_HINT, args = listOf("secret")),
            CandidateInput("open_stdin", CandidateSource.STATIC_HINT, stdin = "open\n".toByteArray()),
        )

        val report = OutputCoverageMeasurer().measure(binary, baseline, expanded)

        assertTrue(report.increased)
        assertEquals(1, report.baselineSignatures.size)
        assertTrue(report.expandedSignatures.size >= 3)
        assertTrue(report.newSignatures.size >= 2)
        assertEquals(expanded.size, report.observations.size)
    }

    @Test
    fun `confidence score reflects validation breadth`() {
        val lowCoverage = CoverageReport(1, 1, setOf("0:"), setOf("0:"))
        val highCoverage = CoverageReport(1, 6, setOf("0:"), setOf("a", "b", "c"))

        val low = ConfidenceScorer.score(listOf(CandidateInput("seed", CandidateSource.SEED)), lowCoverage, sandboxed = true)
        val high = ConfidenceScorer.score(
            listOf(
                CandidateInput("seed", CandidateSource.SEED),
                CandidateInput("angr", CandidateSource.ANGR, args = listOf("secret")),
                CandidateInput("static", CandidateSource.STATIC_HINT, stdin = "open\n".toByteArray()),
                CandidateInput("mutation", CandidateSource.MUTATION, args = listOf("SECRET")),
            ),
            highCoverage,
            sandboxed = true,
        )

        assertTrue(high.score > low.score)
        assertEquals(4, high.sourceCount)
        assertEquals(3, high.outputSignatureCount)
        assertEquals(3, high.newOutputSignatureCount)
    }

    @Test
    fun `automatic exploration writes generated input and confidence report`() {
        val tempDir = createTempDirectory("exploration-report-")
        val binary = compileBranchingProgram(tempDir)
        val seed = listOf(CandidateInput("empty", CandidateSource.SEED))

        val report = AutomaticExplorer(angrExplorer = FakeAngrExplorer()).explore(binary, seed, tempDir.resolve("reports"))

        assertTrue(report.coverage.increased)
        assertTrue(report.confidence.score > 0.5)
        assertTrue(report.reportPath.exists())
        val json = report.reportPath.readText()
        val interpretation = Json.parseToJsonElement(json).jsonObject.getValue("confidence").jsonObject
            .getValue("scoreInterpretation").jsonObject
        assertEquals("exploration-breadth", interpretation.getValue("kind").jsonPrimitive.content)
        assertEquals("uncalibrated", interpretation.getValue("calibrationStatus").jsonPrimitive.content)
        assertEquals(JsonNull, interpretation.getValue("calibratedProbability"))
        assertEquals(JsonNull, interpretation.getValue("calibrationArtifactSha256"))
        assertTrue(json.contains("\"source\": \"ANGR\""))
        assertTrue(json.contains("\"source\": \"STATIC_HINT\""))
        assertTrue(json.contains("\"source\": \"MUTATION\""))
        assertTrue(json.contains("\"coverageIncreased\": true"))
        assertTrue(json.contains("\"sandboxed\": true"))
        assertTrue(json.contains("\"confidence\""))
        assertTrue(json.contains("\"outputSignatureCount\""))
        assertTrue(json.contains("\"newOutputSignatures\""))
        assertTrue(json.contains("\"observations\""))
        assertTrue(json.contains("\"argvStates\": 2"))
    }

    @Test
    fun `exploration report round trips all non NUL JSON control characters in arguments`() {
        val tempParent = java.nio.file.Path.of("build", "test-work", "exploration-json-controls").createDirectories()
        val tempDir = java.nio.file.Files.createTempDirectory(tempParent, "case-")
        val binary = compileBranchingProgram(tempDir)
        val argument = (1..31).map { it.toChar() }.joinToString("")
        val seed = CandidateInput("controls", CandidateSource.SEED, args = listOf(argument))
        val noSymbolicCandidates = object : AngrExplorer {
            override fun generate(binaryPath: java.nio.file.Path): List<CandidateInput> = emptyList()
        }
        val report = AutomaticExplorer(angrExplorer = noSymbolicCandidates, maxCandidates = 1)
            .explore(binary, listOf(seed), tempDir.resolve("reports"))

        val candidate = Json.parseToJsonElement(report.reportPath.readText()).jsonObject
            .getValue("candidates").jsonArray.single().jsonObject
        assertEquals(seed.id, candidate.getValue("id").jsonPrimitive.content)
        assertEquals(argument, candidate.getValue("args").jsonArray.single().jsonPrimitive.content)
    }

    private class FakeAngrExplorer : AngrExplorer {
        override val diagnostics = AngrDiagnostics(argvStates = 2, stdinStates = 2, argvSteps = 10, stdinSteps = 12)

        override fun generate(binaryPath: java.nio.file.Path): List<CandidateInput> =
            listOf(
                CandidateInput("angr_secret_arg", CandidateSource.ANGR, args = listOf("secret")),
                CandidateInput("angr_open_stdin", CandidateSource.ANGR, stdin = "open\n".toByteArray()),
            )
    }

    private fun compileBranchingProgram(tempDir: java.nio.file.Path): java.nio.file.Path {
        val buildDir = tempDir.resolve("branching").createDirectories()
        val sourcePath = buildDir.resolve("branching.c")
        val binaryPath = buildDir.resolve("branching")
        sourcePath.writeText(
            """
            #include <stdio.h>
            #include <string.h>

            int main(int argc, char **argv) {
                char buf[64] = {0};
                if (argc > 1 && strcmp(argv[1], "secret") == 0) {
                    puts("ARG_SECRET");
                    return 2;
                }
                if (fgets(buf, sizeof(buf), stdin) && strcmp(buf, "open\n") == 0) {
                    puts("STDIN_OPEN");
                    return 3;
                }
                puts("DEFAULT");
                return 0;
            }
            """.trimIndent() + "\n",
        )
        val process = ProcessBuilder("gcc", sourcePath.pathString, "-o", binaryPath.pathString)
            .redirectErrorStream(true)
            .start()
        val output = process.inputStream.bufferedReader().readText()
        val exitCode = process.waitFor()
        check(exitCode == 0) { "gcc failed: $output" }
        return binaryPath
    }
}
