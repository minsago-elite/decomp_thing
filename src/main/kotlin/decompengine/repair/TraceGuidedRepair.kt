package decompengine.repair

import decompengine.validation.BehaviorCaseResult
import decompengine.validation.BehaviorComparator
import decompengine.validation.ProcessInput
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.exists
import kotlin.io.path.name
import kotlin.io.path.pathString
import kotlin.io.path.readText
import kotlin.io.path.writeText

data class StreamDiff(
    val expectedHex: String,
    val actualHex: String,
    val firstDifferenceOffset: Int?,
)

data class CaseDiff(
    val id: String,
    val args: List<String>,
    val stdinHex: String,
    val exitCodeExpected: Int,
    val exitCodeActual: Int,
    val exitCodeMatches: Boolean,
    val stdout: StreamDiff,
    val stderr: StreamDiff,
    val matches: Boolean,
)

data class StructuredBehaviorDiff(
    val id: String,
    val cases: List<CaseDiff>,
) {
    val matches: Boolean = cases.all { it.matches }
}

data class CompileFailure(
    val command: List<String>,
    val exitCode: Int,
    val stdout: String,
    val stderr: String,
) {
    fun toPrompt(): String = """
        Compile command: ${command.joinToString(" ")}
        Exit code: $exitCode
        stdout:
        $stdout
        stderr:
        $stderr
    """.trimIndent()
}

data class SourcePatch(
    val relativePath: String,
    val replacement: String,
)

data class RepairRequest(
    val failureKind: String,
    val prompt: String,
    val projectFiles: Map<String, String>,
    val regressionInputs: List<ProcessInput>,
)

data class RepairResponse(
    val summary: String,
    val patches: List<SourcePatch>,
)

interface RepairClient {
    fun requestRepair(request: RepairRequest): RepairResponse
}

class HttpOpenAiCompatibleRepairClient(
    private val apiKey: String,
    private val model: String,
    baseUrl: URI,
    reasoningEffort: String? = null,
    private val httpClient: HttpClient = HttpClient.newHttpClient(),
) : RepairClient {
    private val endpoint = URI.create(baseUrl.toString().trimEnd('/') + "/chat/completions")
    private val reasoningEffort = reasoningEffort?.trim()?.takeIf { it.isNotEmpty() }

    init {
        require(apiKey.isNotBlank()) { "API_KEY must not be blank" }
        require(model.isNotBlank()) { "MODEL must not be blank" }
        require(baseUrl.scheme in setOf("http", "https") && !baseUrl.host.isNullOrBlank()) {
            "BASE_URL must be an absolute HTTP(S) URL"
        }
        require(this.reasoningEffort == null || this.reasoningEffort in SUPPORTED_REASONING_EFFORTS) {
            "REASONING_EFFORT must be one of ${SUPPORTED_REASONING_EFFORTS.joinToString(", ")}"
        }
    }

    override fun requestRepair(request: RepairRequest): RepairResponse {
        val reasoningLine = reasoningEffort?.let { "  \"reasoning_effort\": \"${it.escapeJson()}\",\n" }.orEmpty()
        val body = """
            {
              "model": "${model.escapeJson()}",
            $reasoningLine  "messages": [
                {
                  "role": "system",
                  "content": "Return source patches as JSON with summary and patches. Each patch has relativePath and replacement."
                },
                {
                  "role": "user",
                  "content": "${request.toPrompt().escapeJson()}"
                }
              ]
            }
        """.trimIndent()
        val httpRequest = HttpRequest.newBuilder(endpoint)
            .header("Authorization", "Bearer $apiKey")
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build()
        val response = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString())
        if (response.statusCode() !in 200..299) {
            error("OpenAI-compatible repair request failed with HTTP ${response.statusCode()}: ${response.body()}")
        }
        return parseRepairResponse(extractMessageContent(response.body()))
    }

    private fun RepairRequest.toPrompt(): String = """
        Failure kind: $failureKind

        Failure details:
        $prompt

        Regression inputs:
        ${regressionInputs.joinToString("\n") { "- ${it.id}: args=${it.args} stdinHex=${it.stdin.toHex()}" }}

        Project files:
        ${projectFiles.entries.joinToString("\n\n") { "### ${it.key}\n${it.value}" }}
    """.trimIndent()

    private fun extractMessageContent(body: String): String {
        val marker = "\"content\""
        val markerIndex = body.indexOf(marker)
        if (markerIndex < 0) error("OpenAI-compatible response did not include message content")
        val colon = body.indexOf(':', markerIndex)
        val firstQuote = body.indexOf('"', colon + 1)
        val result = StringBuilder()
        var index = firstQuote + 1
        var escaped = false
        while (index < body.length) {
            val char = body[index++]
            if (escaped) {
                result.append(
                    when (char) {
                        'n' -> '\n'
                        'r' -> '\r'
                        't' -> '\t'
                        '"' -> '"'
                        '\\' -> '\\'
                        else -> char
                    },
                )
                escaped = false
            } else if (char == '\\') {
                escaped = true
            } else if (char == '"') {
                return result.toString()
            } else {
                result.append(char)
            }
        }
        error("OpenAI-compatible response content string was unterminated")
    }

    private fun parseRepairResponse(content: String): RepairResponse {
        val summary = content.substringAfter("\"summary\"", "").substringAfter(':', "").substringAfter('"', "")
            .substringBefore('"')
            .ifBlank { "OpenAI-compatible repair response" }
        val patches = Regex(
            "\\{\\s*\"relativePath\"\\s*:\\s*\"((?:\\\\.|[^\"])*)\"\\s*,\\s*\"replacement\"\\s*:\\s*\"((?:\\\\.|[^\"])*)\"\\s*}",
            RegexOption.DOT_MATCHES_ALL,
        ).findAll(content).map {
            SourcePatch(it.groupValues[1].unescapeJson(), it.groupValues[2].unescapeJson())
        }.toList()
        if (patches.isEmpty()) error("OpenAI-compatible response did not include source patches")
        return RepairResponse(summary = summary, patches = patches)
    }

    companion object {
        fun fromEnvironment(environment: Map<String, String> = System.getenv()): HttpOpenAiCompatibleRepairClient =
            HttpOpenAiCompatibleRepairClient(
                apiKey = environment["API_KEY"].orEmpty(),
                model = environment["MODEL"].orEmpty(),
                baseUrl = URI.create(environment["BASE_URL"].orEmpty()),
                reasoningEffort = environment["REASONING_EFFORT"],
            )

        private val SUPPORTED_REASONING_EFFORTS = setOf("none", "minimal", "low", "medium", "high", "xhigh")
    }
}

object StructuredDiffBuilder {
    fun from(id: String, cases: List<BehaviorCaseResult>): StructuredBehaviorDiff =
        StructuredBehaviorDiff(
            id = id,
            cases = cases.map {
                CaseDiff(
                    id = it.input.id,
                    args = it.input.args,
                    stdinHex = it.input.stdin.toHex(),
                    exitCodeExpected = it.original.exitCode,
                    exitCodeActual = it.rebuilt.exitCode,
                    exitCodeMatches = it.exitCodeMatches,
                    stdout = streamDiff(it.original.stdout, it.rebuilt.stdout),
                    stderr = streamDiff(it.original.stderr, it.rebuilt.stderr),
                    matches = it.matches,
                )
            },
        )

    private fun streamDiff(expected: ByteArray, actual: ByteArray): StreamDiff =
        StreamDiff(
            expectedHex = expected.toHex(),
            actualHex = actual.toHex(),
            firstDifferenceOffset = firstDifferenceOffset(expected, actual),
        )

    private fun firstDifferenceOffset(expected: ByteArray, actual: ByteArray): Int? {
        val limit = minOf(expected.size, actual.size)
        for (index in 0 until limit) {
            if (expected[index] != actual[index]) return index
        }
        return if (expected.size == actual.size) null else limit
    }
}

data class RepairIteration(
    val index: Int,
    val failureKind: String,
    val prompt: String,
    val summary: String,
    val patches: List<SourcePatch>,
    val retainedRegressionIds: List<String>,
)

class RepairHistory(private val path: Path) {
    private val iterations = mutableListOf<RepairIteration>()

    fun append(iteration: RepairIteration) {
        iterations += iteration
        path.parent.createDirectories()
        path.writeText(toJson())
    }

    fun all(): List<RepairIteration> = iterations.toList()

    fun toJson(): String = """
        {
          "iterations": [
        ${iterations.joinToString(",\n") { it.toJson().prependIndent("    ") }}
          ]
        }
    """.trimIndent() + "\n"
}

class TraceGuidedRepairLoop(
    private val client: RepairClient,
    private val history: RepairHistory,
) {
    fun repairCompileError(projectDir: Path, failure: CompileFailure, regressionInputs: List<ProcessInput>): RepairIteration {
        val request = RepairRequest(
            failureKind = "compile",
            prompt = failure.toPrompt(),
            projectFiles = projectSources(projectDir),
            regressionInputs = regressionInputs,
        )
        return applyRepair(projectDir, request)
    }

    fun repairBehaviorMismatch(
        projectDir: Path,
        originalBinary: Path,
        rebuiltBinary: Path,
        inputs: List<ProcessInput>,
        reportsDir: Path,
    ): RepairIteration {
        val comparison = try {
            BehaviorComparator().compare("behavior_repair", originalBinary, rebuiltBinary, inputs, reportsDir)
        } catch (_: RuntimeException) {
            val report = BehaviorComparatorNoThrow().compare("behavior_repair", originalBinary, rebuiltBinary, inputs, reportsDir)
            val diff = StructuredDiffBuilder.from("behavior_repair", report.cases)
            val request = RepairRequest(
                failureKind = "behavior",
                prompt = diff.toPrompt(),
                projectFiles = projectSources(projectDir),
                regressionInputs = inputs,
            )
            return applyRepair(projectDir, request)
        }
        error("behavior already matched for ${comparison.id}; no repair needed")
    }

    private fun applyRepair(projectDir: Path, request: RepairRequest): RepairIteration {
        val response = client.requestRepair(request)
        response.patches.forEach { patch ->
            val target = projectDir.resolve(patch.relativePath).normalize()
            require(target.startsWith(projectDir.normalize())) { "patch escapes project dir: ${patch.relativePath}" }
            target.parent.createDirectories()
            target.writeText(patch.replacement)
        }
        val iteration = RepairIteration(
            index = history.all().size + 1,
            failureKind = request.failureKind,
            prompt = request.prompt,
            summary = response.summary,
            patches = response.patches,
            retainedRegressionIds = request.regressionInputs.map { it.id },
        )
        history.append(iteration)
        return iteration
    }

    private fun projectSources(projectDir: Path): Map<String, String> =
        listOf("Makefile", "src/main.c", "src/reconstructed.c", "include/decomp_engine.h")
            .mapNotNull { relative ->
                val path = projectDir.resolve(relative)
                if (path.exists()) relative to path.readText() else null
            }
            .toMap()
}

private class BehaviorComparatorNoThrow {
    fun compare(
        id: String,
        originalBinary: Path,
        rebuiltBinary: Path,
        cases: List<ProcessInput>,
        reportsDir: Path,
    ) = runCatching {
        BehaviorComparator().compare(id, originalBinary, rebuiltBinary, cases, reportsDir)
    }.getOrElse {
        val reportPath = reportsDir.resolve("$id.behavior.json")
        val results = cases.map { input ->
            val runner = decompengine.validation.SandboxRunner()
            BehaviorCaseResult(input, runner.run(originalBinary, input), runner.run(rebuiltBinary, input))
        }
        decompengine.validation.BehaviorComparisonReport(id, originalBinary, rebuiltBinary, results, reportPath).also {
            reportPath.writeText("""{"id":"$id","matches":${it.matches}}""" + "\n")
        }
    }
}

fun StructuredBehaviorDiff.toPrompt(): String = """
    Structured behavior diff for $id:
    ${cases.joinToString("\n") {
        "- ${it.id}: exit expected=${it.exitCodeExpected} actual=${it.exitCodeActual}; " +
            "stdout offset=${it.stdout.firstDifferenceOffset} expected=${it.stdout.expectedHex} actual=${it.stdout.actualHex}; " +
            "stderr offset=${it.stderr.firstDifferenceOffset} expected=${it.stderr.expectedHex} actual=${it.stderr.actualHex}"
    }}
""".trimIndent()

private fun RepairIteration.toJson(): String = """
{
  "index": $index,
  "failureKind": "${failureKind.escapeJson()}",
  "summary": "${summary.escapeJson()}",
  "retainedRegressionIds": [${retainedRegressionIds.joinToString(", ") { "\"${it.escapeJson()}\"" }}],
  "patches": [
${patches.joinToString(",\n") { it.toJson().prependIndent("    ") }}
  ]
}
""".trimIndent()

private fun SourcePatch.toJson(): String = """
{
  "relativePath": "${relativePath.escapeJson()}",
  "replacement": "${replacement.escapeJson()}"
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

private fun String.unescapeJson(): String {
    val result = StringBuilder()
    var index = 0
    while (index < length) {
        val char = this[index++]
        if (char == '\\' && index < length) {
            result.append(
                when (val escaped = this[index++]) {
                    'n' -> '\n'
                    'r' -> '\r'
                    't' -> '\t'
                    '"' -> '"'
                    '\\' -> '\\'
                    else -> escaped
                },
            )
        } else {
            result.append(char)
        }
    }
    return result.toString()
}
