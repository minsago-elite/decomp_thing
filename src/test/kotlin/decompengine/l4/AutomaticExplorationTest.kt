package decompengine.l4

import decompengine.l2.ProcessInput
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.pathString
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class AutomaticExplorationTest {
    @Test
    fun `angr explorer creates candidate argv and stdin cases through adapter boundary`() {
        val candidates = FakeAngrExplorer().generate(java.nio.file.Path.of("/tmp/fake"))

        assertTrue(candidates.any { it.source == CandidateSource.ANGR && it.args == listOf("secret") })
        assertTrue(candidates.any { it.source == CandidateSource.ANGR && it.stdin.contentEquals("open\n".toByteArray()) })
    }

    @Test
    fun `string static-hint input generation works`() {
        val tempDir = createTempDirectory("l4-static-")
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
    }

    @Test
    fun `generated tests increase path and output coverage`() {
        val tempDir = createTempDirectory("l4-coverage-")
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
    }

    @Test
    fun `automatic exploration writes generated input and confidence report`() {
        val tempDir = createTempDirectory("l4-report-")
        val binary = compileBranchingProgram(tempDir)
        val seed = listOf(CandidateInput("empty", CandidateSource.SEED))

        val report = AutomaticExplorer(angrExplorer = FakeAngrExplorer()).explore(binary, seed, tempDir.resolve("reports"))

        assertTrue(report.coverage.increased)
        assertTrue(report.confidence.score > 0.5)
        assertTrue(report.reportPath.exists())
        val json = report.reportPath.readText()
        assertTrue(json.contains("\"source\": \"ANGR\""))
        assertTrue(json.contains("\"source\": \"STATIC_HINT\""))
        assertTrue(json.contains("\"source\": \"MUTATION\""))
        assertTrue(json.contains("\"coverageIncreased\": true"))
    }

    private class FakeAngrExplorer : AngrExplorer {
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
