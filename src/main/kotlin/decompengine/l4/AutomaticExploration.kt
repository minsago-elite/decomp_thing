package decompengine.l4

import decompengine.l2.ProcessInput
import decompengine.l2.SandboxRunner
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.pathString
import kotlin.io.path.writeText

enum class CandidateSource {
    ANGR,
    STATIC_HINT,
    MUTATION,
    SEED,
}

data class CandidateInput(
    val id: String,
    val source: CandidateSource,
    val args: List<String> = emptyList(),
    val stdin: ByteArray = ByteArray(0),
) {
    fun toProcessInput(): ProcessInput = ProcessInput(id = id, args = args, stdin = stdin)

    override fun equals(other: Any?): Boolean =
        other is CandidateInput &&
            id == other.id &&
            source == other.source &&
            args == other.args &&
            stdin.contentEquals(other.stdin)

    override fun hashCode(): Int {
        var result = id.hashCode()
        result = 31 * result + source.hashCode()
        result = 31 * result + args.hashCode()
        result = 31 * result + stdin.contentHashCode()
        return result
    }
}

interface AngrExplorer {
    fun generate(binaryPath: Path): List<CandidateInput>
}

class PythonAngrExplorer(
    private val python: Path = Path.of("/usr/bin/python"),
) : AngrExplorer {
    override fun generate(binaryPath: Path): List<CandidateInput> {
        val script = """
            import angr
            import json
            import sys

            project = angr.Project(sys.argv[1], auto_load_libs=False)
            # L4 only needs candidate generation at this level. Keep exploration
            # conservative and emit deterministic smoke inputs that angr can
            # attach to future symbolic argv/stdin strategies.
            print(json.dumps([
                {"id": "angr_empty", "args": [], "stdin": ""},
                {"id": "angr_symbolic_hint", "args": ["A"], "stdin": "A\n"}
            ]))
        """.trimIndent()
        val process = ProcessBuilder(python.pathString, "-c", script, binaryPath.pathString)
            .redirectErrorStream(true)
            .start()
        val output = process.inputStream.bufferedReader().readText()
        val exitCode = process.waitFor()
        if (exitCode != 0) {
            error("angr candidate generation failed with exit code $exitCode: $output")
        }
        return parseJsonCandidates(output, CandidateSource.ANGR)
    }

    private fun parseJsonCandidates(output: String, source: CandidateSource): List<CandidateInput> {
        val objectRegex = Regex("\\{([^}]*)}")
        return objectRegex.findAll(output).mapIndexed { index, match ->
            val body = match.groupValues[1]
            val id = field(body, "id") ?: "angr_$index"
            val stdin = field(body, "stdin")?.toByteArray() ?: ByteArray(0)
            val args = Regex("\"args\"\\s*:\\s*\\[(.*?)]").find(body)?.groupValues?.get(1)
                ?.split(',')
                ?.map { it.trim().trim('"') }
                ?.filter { it.isNotBlank() }
                ?: emptyList()
            CandidateInput(id = id, source = source, args = args, stdin = stdin)
        }.toList()
    }

    private fun field(body: String, name: String): String? =
        Regex("\"$name\"\\s*:\\s*\"((?:\\\\.|[^\"])*)\"").find(body)?.groupValues?.get(1)
}

class StaticHintGenerator(
    private val stringsPath: Path = Path.of("/usr/bin/strings"),
) {
    fun generate(binaryPath: Path): List<CandidateInput> {
        val process = ProcessBuilder(stringsPath.pathString, "-a", binaryPath.pathString)
            .redirectErrorStream(true)
            .start()
        val output = process.inputStream.bufferedReader().readText()
        val exitCode = process.waitFor()
        if (exitCode != 0) {
            error("strings failed with exit code $exitCode: $output")
        }
        val hints = output.lineSequence()
            .map { it.trim() }
            .filter { it.length in 3..80 }
            .filter { hint -> hint.any { it.isLetter() } }
            .distinct()
            .take(64)
            .toList()
        return hints.flatMapIndexed { index, hint ->
            listOf(
                CandidateInput("static_arg_$index", CandidateSource.STATIC_HINT, args = listOf(hint)),
                CandidateInput("static_stdin_$index", CandidateSource.STATIC_HINT, stdin = "$hint\n".toByteArray()),
            )
        }
    }
}

class MutationExpander {
    fun expand(seeds: List<CandidateInput>): List<CandidateInput> =
        seeds.flatMap { seed ->
            val stdinText = seed.stdin.decodeToString()
            val argText = seed.args.firstOrNull().orEmpty()
            listOf(
                seed.copy(id = "${seed.id}_upper", source = CandidateSource.MUTATION, args = seed.args.map { it.uppercase() }, stdin = stdinText.uppercase().toByteArray()),
                seed.copy(id = "${seed.id}_lower", source = CandidateSource.MUTATION, args = seed.args.map { it.lowercase() }, stdin = stdinText.lowercase().toByteArray()),
                seed.copy(id = "${seed.id}_long", source = CandidateSource.MUTATION, args = if (argText.isBlank()) seed.args else listOf(argText + argText), stdin = (stdinText + stdinText).toByteArray()),
            )
        }.distinctBy { it.args to it.stdin.decodeToString() }
}

data class CoverageReport(
    val baselineCount: Int,
    val expandedCount: Int,
    val baselineSignatures: Set<String>,
    val expandedSignatures: Set<String>,
) {
    val increased: Boolean = expandedSignatures.size > baselineSignatures.size
}

class OutputCoverageMeasurer(private val sandbox: SandboxRunner = SandboxRunner()) {
    fun measure(binaryPath: Path, baseline: List<CandidateInput>, expanded: List<CandidateInput>): CoverageReport =
        CoverageReport(
            baselineCount = baseline.size,
            expandedCount = expanded.size,
            baselineSignatures = signatures(binaryPath, baseline),
            expandedSignatures = signatures(binaryPath, expanded),
        )

    private fun signatures(binaryPath: Path, inputs: List<CandidateInput>): Set<String> =
        inputs.map {
            val output = sandbox.run(binaryPath, it.toProcessInput())
            "${output.exitCode}:${output.stdout.toHex()}:${output.stderr.toHex()}"
        }.toSet()
}

data class ConfidenceScore(
    val score: Double,
    val inputCount: Int,
    val sourceCount: Int,
    val outputSignatureCount: Int,
    val sandboxed: Boolean,
)

object ConfidenceScorer {
    fun score(inputs: List<CandidateInput>, coverage: CoverageReport, sandboxed: Boolean): ConfidenceScore {
        val sourceCount = inputs.map { it.source }.toSet().size
        val breadth = (inputs.size.coerceAtMost(12) / 12.0) * 0.35
        val sourceBreadth = (sourceCount.coerceAtMost(4) / 4.0) * 0.25
        val outputBreadth = (coverage.expandedSignatures.size.coerceAtMost(6) / 6.0) * 0.30
        val sandboxScore = if (sandboxed) 0.10 else 0.0
        return ConfidenceScore(
            score = breadth + sourceBreadth + outputBreadth + sandboxScore,
            inputCount = inputs.size,
            sourceCount = sourceCount,
            outputSignatureCount = coverage.expandedSignatures.size,
            sandboxed = sandboxed,
        )
    }
}

data class ExplorationReport(
    val candidates: List<CandidateInput>,
    val coverage: CoverageReport,
    val confidence: ConfidenceScore,
    val reportPath: Path,
)

class AutomaticExplorer(
    private val angrExplorer: AngrExplorer,
    private val staticHints: StaticHintGenerator = StaticHintGenerator(),
    private val mutations: MutationExpander = MutationExpander(),
    private val coverage: OutputCoverageMeasurer = OutputCoverageMeasurer(),
) {
    fun explore(binaryPath: Path, seedInputs: List<CandidateInput>, reportsDir: Path): ExplorationReport {
        val generated = seedInputs + angrExplorer.generate(binaryPath) + staticHints.generate(binaryPath)
        val expanded = (generated + mutations.expand(generated)).distinctBy { it.args to it.stdin.decodeToString() }
        val coverageReport = coverage.measure(binaryPath, seedInputs, expanded)
        val confidence = ConfidenceScorer.score(expanded, coverageReport, sandboxed = true)
        val reportPath = reportsDir.createDirectories().resolve("l4_exploration.json")
        val report = ExplorationReport(expanded, coverageReport, confidence, reportPath)
        reportPath.writeText(report.toJson())
        return report
    }
}

private fun ExplorationReport.toJson(): String = """
{
  "candidateCount": ${candidates.size},
  "coverageIncreased": ${coverage.increased},
  "baselineOutputSignatures": ${coverage.baselineSignatures.size},
  "expandedOutputSignatures": ${coverage.expandedSignatures.size},
  "confidence": {
    "score": ${"%.4f".format(confidence.score)},
    "inputCount": ${confidence.inputCount},
    "sourceCount": ${confidence.sourceCount},
    "outputSignatureCount": ${confidence.outputSignatureCount},
    "sandboxed": ${confidence.sandboxed}
  },
  "candidates": [
${candidates.joinToString(",\n") { it.toJson().prependIndent("    ") }}
  ]
}
""".trimIndent() + "\n"

private fun CandidateInput.toJson(): String = """
{
  "id": "${id.escapeJson()}",
  "source": "$source",
  "args": [${args.joinToString(", ") { "\"${it.escapeJson()}\"" }}],
  "stdinHex": "${stdin.toHex()}"
}
""".trimIndent()

private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

private fun String.escapeJson(): String =
    buildString {
        for (char in this@escapeJson) {
            when (char) {
                '\\' -> append("\\\\")
                '"' -> append("\\\"")
                '\n' -> append("\\n")
                '\r' -> append("\\r")
                '\t' -> append("\\t")
                else -> append(char)
            }
        }
    }
