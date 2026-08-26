package decompengine.repair

import decompengine.validation.BehaviorCaseResult
import decompengine.validation.BehaviorComparator
import decompengine.validation.BehaviorComparisonReport
import decompengine.validation.ProcessInput
import decompengine.project.SourceTreeManifestReader
import decompengine.project.sha256
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Path
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.util.concurrent.CompletableFuture
import kotlin.io.path.createDirectories
import kotlin.io.path.exists
import kotlin.io.path.name
import kotlin.io.path.pathString
import kotlin.io.path.readText
import kotlin.io.path.readBytes
import kotlin.io.path.isRegularFile
import kotlin.io.path.relativeTo
import kotlin.io.path.writeText
import kotlin.io.path.writeBytes

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
    fun modelIdentifier(): String? = null
}

class HttpOpenAiCompatibleRepairClient(
    private val apiKey: String,
    private val model: String,
    baseUrl: URI,
    reasoningEffort: String? = null,
    private val httpClient: HttpClient = HttpClient.newHttpClient(),
) : RepairClient {
    override fun modelIdentifier(): String = model
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

    private fun extractMessageContent(body: String): String = runCatching {
        Json.parseToJsonElement(body).jsonObject
            .getValue("choices").jsonArray.first().jsonObject
            .getValue("message").jsonObject
            .getValue("content").jsonPrimitive.content
    }.getOrElse { throw IllegalStateException("OpenAI-compatible response did not include valid message content", it) }

    private fun parseRepairResponse(content: String): RepairResponse {
        val normalized = content.trim().removeSurrounding("```json", "```").trim()
        val response = runCatching { Json.parseToJsonElement(normalized).jsonObject }
            .getOrElse { throw IllegalStateException("OpenAI-compatible message content was not valid patch JSON", it) }
        val summary = response["summary"]?.jsonPrimitive?.contentOrNull?.ifBlank { null }
            ?: "OpenAI-compatible repair response"
        val patches = response["patches"]?.jsonArray?.map { item ->
            val patch = item.jsonObject
            SourcePatch(
                relativePath = patch.getValue("relativePath").jsonPrimitive.content,
                replacement = patch.getValue("replacement").jsonPrimitive.content,
            )
        }.orEmpty()
        if (patches.isEmpty()) error("OpenAI-compatible response did not include source patches")
        return RepairResponse(summary, patches)
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
    val before: RepairEvidence? = null,
    val after: RepairEvidence? = null,
    val succeeded: Boolean = false,
)

data class RepairEvidence(
    val kind: String,
    val summary: String,
    val artifactPath: String? = null,
)

data class RepairRunResult(
    val iterations: List<RepairIteration>,
    val validation: BehaviorComparisonReport,
)

class RepairExhaustedException(message: String) : RuntimeException(message)

class RepairHistory(private val path: Path) {
    private val iterations = mutableListOf<RepairIteration>()
    private val regressionInputs = mutableListOf<ProcessInput>()

    init {
        if (path.exists()) load(path.readText())
    }

    fun retain(inputs: List<ProcessInput>) {
        inputs.forEach { candidate ->
            val existing = regressionInputs.indexOfFirst { it.id == candidate.id }
            require(existing < 0 || regressionInputs[existing] == candidate) {
                "regression input id ${candidate.id} refers to different input data"
            }
            if (existing < 0) regressionInputs += candidate
        }
        persist()
    }

    fun append(iteration: RepairIteration) {
        iterations += iteration
        persist()
    }

    fun all(): List<RepairIteration> = iterations.toList()
    fun retainedInputs(): List<ProcessInput> = regressionInputs.toList()

    fun toJson(): String = """
        {
          "regressionInputs": [
        ${regressionInputs.joinToString(",\n") { it.toJson().prependIndent("    ") }}
          ],
          "iterations": [
        ${iterations.joinToString(",\n") { it.toJson().prependIndent("    ") }}
          ]
        }
    """.trimIndent() + "\n"

    private fun persist() {
        path.parent.createDirectories()
        path.writeText(toJson())
    }

    private fun load(payload: String) {
        val root = runCatching { Json.parseToJsonElement(payload).jsonObject }
            .getOrElse { error("invalid repair history at ${path.pathString}: ${it.message}") }
        root["regressionInputs"]?.jsonArray?.map(::parseProcessInput)?.let(regressionInputs::addAll)
        root["iterations"]?.jsonArray?.map(::parseIteration)?.let(iterations::addAll)
    }
}

class TraceGuidedRepairLoop(
    private val client: RepairClient,
    private val history: RepairHistory,
) {
    fun repairCompileError(projectDir: Path, failure: CompileFailure, regressionInputs: List<ProcessInput>): RepairIteration {
        history.retain(regressionInputs)
        val request = RepairRequest(
            failureKind = "compile",
            prompt = failure.toPrompt(),
            projectFiles = projectSources(projectDir, failure.stdout + "\n" + failure.stderr),
            regressionInputs = history.retainedInputs(),
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
        history.retain(inputs)
        val comparison = BehaviorComparator().evaluate(
            "behavior_repair",
            originalBinary,
            rebuiltBinary,
            history.retainedInputs(),
            reportsDir,
        )
        if (comparison.matches) error("behavior already matched for ${comparison.id}; no repair needed")
        val diff = StructuredDiffBuilder.from("behavior_repair", comparison.cases)
        val diffPath = reportsDir.resolve("behavior_repair.diff.json")
        diffPath.writeText(diff.toJson())
        val request = RepairRequest(
            failureKind = "behavior",
            prompt = diff.toPrompt(),
            projectFiles = projectSources(projectDir),
            regressionInputs = history.retainedInputs(),
        )
        return applyRepair(
            projectDir,
            request,
            before = RepairEvidence("behavior", "${diff.cases.count { !it.matches }} mismatched case(s)", diffPath.pathString),
        )
    }

    fun repairUntilValid(
        projectDir: Path,
        originalBinary: Path,
        inputs: List<ProcessInput>,
        reportsDir: Path = projectDir.resolve("reports"),
        maxIterations: Int = 5,
    ): RepairRunResult {
        require(maxIterations > 0) { "maxIterations must be positive" }
        history.retain(inputs)
        reportsDir.createDirectories()
        val startedAt = history.all().size
        var assessment = assess(projectDir, originalBinary, reportsDir, "initial")
        if (assessment is RepairAssessment.Valid) {
            return RepairRunResult(emptyList(), assessment.report)
        }

        repeat(maxIterations) { offset ->
            val request = assessment.toRequest(projectSources(projectDir, assessment.contextHint()), history.retainedInputs())
            val response = client.requestRepair(request)
            val applied = applyPatches(projectDir, response.patches)
            val after = assess(projectDir, originalBinary, reportsDir, "iteration_${startedAt + offset + 1}")
            val rolledBack = assessment !is RepairAssessment.CompileError && after is RepairAssessment.CompileError
            if (rolledBack) rollbackPatches(projectDir, applied)
            val iteration = RepairIteration(
                index = history.all().size + 1,
                failureKind = request.failureKind,
                prompt = request.prompt,
                summary = response.summary,
                patches = response.patches,
                retainedRegressionIds = history.retainedInputs().map { it.id },
                before = assessment.evidence,
                after = after.evidence,
                succeeded = after is RepairAssessment.Valid,
            )
            history.append(iteration)
            recordRevisions(projectDir, iteration.index, applied, after.evidence, after is RepairAssessment.Valid)
            if (after is RepairAssessment.Valid) {
                return RepairRunResult(history.all().drop(startedAt), after.report)
            }
            assessment = if (rolledBack) assessment else after
        }
        throw RepairExhaustedException(
            "repair did not converge after $maxIterations iteration(s); see ${reportsDir.resolve("repair_history.json")}",
        )
    }

    private fun applyRepair(
        projectDir: Path,
        request: RepairRequest,
        before: RepairEvidence? = null,
    ): RepairIteration {
        val response = client.requestRepair(request)
        val applied = applyPatches(projectDir, response.patches)
        val iteration = RepairIteration(
            index = history.all().size + 1,
            failureKind = request.failureKind,
            prompt = request.prompt,
            summary = response.summary,
            patches = response.patches,
            retainedRegressionIds = request.regressionInputs.map { it.id },
            before = before,
        )
        history.append(iteration)
        recordRevisions(projectDir, iteration.index, applied, before, accepted = false)
        return iteration
    }

    private data class AppliedPatch(val path: String, val beforeSha256: String, val afterSha256: String, val beforeContent: ByteArray)

    private fun applyPatches(projectDir: Path, patches: List<SourcePatch>): List<AppliedPatch> {
        require(patches.isNotEmpty()) { "repair response contained no patches" }
        val manifestOwned = SourceTreeManifestReader.editablePaths(projectDir)
        val allowed = if (manifestOwned.isNotEmpty()) manifestOwned else projectSources(projectDir).keys
        require(patches.map { it.relativePath }.distinct().size == patches.size) { "repair response patches a file more than once" }
        val base = projectDir.toAbsolutePath().normalize()
        val targets = patches.map { patch ->
            require(patch.relativePath in allowed) { "patch targets an unknown project file: ${patch.relativePath}" }
            val target = base.resolve(patch.relativePath).normalize()
            require(target.startsWith(base)) {
                "patch escapes project dir: ${patch.relativePath}"
            }
            patch to target
        }
        val originals = targets.associate { (_, target) -> target to target.readBytes() }
        val staged = targets.map { (patch, target) ->
            target.parent.createDirectories()
            val temporary = Files.createTempFile(target.parent, ".${target.fileName}.", ".repair")
            temporary.writeText(patch.replacement)
            Triple(patch, target, temporary)
        }
        try {
            staged.forEach { (_, target, temporary) ->
                runCatching {
                    Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
                }.getOrElse {
                    Files.move(temporary, target, StandardCopyOption.REPLACE_EXISTING)
                }
            }
        } catch (failure: Exception) {
            originals.forEach { (target, bytes) -> runCatching { target.writeBytes(bytes) } }
            staged.forEach { (_, _, temporary) -> runCatching { Files.deleteIfExists(temporary) } }
            throw failure
        }
        return targets.map { (patch, target) ->
            val before = originals.getValue(target)
            AppliedPatch(patch.relativePath, sha256(before), sha256(patch.replacement.toByteArray()), before)
        }
    }

    private fun rollbackPatches(projectDir: Path, patches: List<AppliedPatch>) {
        val base = projectDir.toAbsolutePath().normalize()
        patches.forEach { patch ->
            val target = base.resolve(patch.path).normalize()
            require(target.startsWith(base)) { "rollback path escapes project: ${patch.path}" }
            target.writeBytes(patch.beforeContent)
        }
    }

    private fun assess(
        projectDir: Path,
        originalBinary: Path,
        reportsDir: Path,
        label: String,
    ): RepairAssessment {
        val compile = compile(projectDir, reportsDir.resolve("$label.compile.log"))
        if (compile != null) return RepairAssessment.CompileError(compile, reportsDir.resolve("$label.compile.log"))
        val rebuilt = projectDir.resolve("build/reconstructed")
        val report = BehaviorComparator().evaluate(
            "${label}_behavior",
            originalBinary,
            rebuilt,
            history.retainedInputs(),
            reportsDir,
        )
        if (report.matches) return RepairAssessment.Valid(report)
        val diff = StructuredDiffBuilder.from(report.id, report.cases)
        val path = reportsDir.resolve("${report.id}.diff.json")
        path.writeText(diff.toJson())
        return RepairAssessment.BehaviorError(diff, path)
    }

    private fun compile(projectDir: Path, logPath: Path): CompileFailure? {
        val command = listOf("make")
        val process = ProcessBuilder(command).directory(projectDir.toFile()).start()
        val stdoutFuture = CompletableFuture.supplyAsync { process.inputStream.bufferedReader().readText() }
        val stderrFuture = CompletableFuture.supplyAsync { process.errorStream.bufferedReader().readText() }
        val exitCode = process.waitFor()
        val stdout = stdoutFuture.join()
        val stderr = stderrFuture.join()
        logPath.writeText(
            "${'$'} make\nexit_code=$exitCode\n\n[stdout]\n$stdout\n[stderr]\n$stderr",
        )
        return if (exitCode == 0) null else CompileFailure(command, exitCode, stdout, stderr)
    }

    private fun projectSources(projectDir: Path, diagnosticHint: String? = null): Map<String, String> {
        val owned = SourceTreeManifestReader.editablePaths(projectDir).ifEmpty {
            Files.walk(projectDir).use { paths ->
                paths.filter { it.isRegularFile() }
                    .map { it.relativeTo(projectDir).pathString.replace('\\', '/') }
                    .filter { it == "Makefile" || it.endsWith(".c") || it.endsWith(".h") }
                    .toList().toSet()
            }
        }
        val hinted = diagnosticHint?.let { hint -> owned.filter { it in hint || Path.of(it).fileName.toString() in hint }.toSet() }.orEmpty()
        val selected = if (hinted.isEmpty()) owned else owned.filter { candidate ->
            candidate in hinted || candidate == "Makefile" || candidate == "include/decomp_types.h" ||
                hinted.any { Path.of(it).fileName.toString().substringBefore('.') == Path.of(candidate).fileName.toString().substringBefore('.') }
        }.toSet()
        return selected.sorted().associateWith { projectDir.resolve(it).readText() }
    }

    private fun recordRevisions(
        projectDir: Path,
        iteration: Int,
        patches: List<AppliedPatch>,
        evidence: RepairEvidence?,
        accepted: Boolean,
    ) {
        val path = projectDir.resolve("reports/source_revisions.jsonl")
        path.parent.createDirectories()
        val lines = patches.joinToString("") { patch ->
            "{\"iteration\":$iteration,\"path\":\"${patch.path.escapeJson()}\",\"beforeSha256\":\"${patch.beforeSha256}\"," +
                "\"afterSha256\":\"${patch.afterSha256}\",\"accepted\":$accepted," +
                "\"evidenceKind\":${evidence?.kind?.let { "\"${it.escapeJson()}\"" } ?: "null"}," +
                "\"evidenceArtifact\":${evidence?.artifactPath?.let { "\"${it.escapeJson()}\"" } ?: "null"}}\n"
        }
        Files.writeString(path, lines, java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND)
    }
}

private sealed interface RepairAssessment {
    val evidence: RepairEvidence

    data class CompileError(val failure: CompileFailure, val logPath: Path) : RepairAssessment {
        override val evidence = RepairEvidence(
            kind = "compile",
            summary = "compiler exited with code ${failure.exitCode}",
            artifactPath = logPath.pathString,
        )
    }

    data class BehaviorError(val diff: StructuredBehaviorDiff, val diffPath: Path) : RepairAssessment {
        override val evidence = RepairEvidence(
            kind = "behavior",
            summary = "${diff.cases.count { !it.matches }} of ${diff.cases.size} regression case(s) mismatched",
            artifactPath = diffPath.pathString,
        )
    }

    data class Valid(val report: BehaviorComparisonReport) : RepairAssessment {
        override val evidence = RepairEvidence(
            kind = "valid",
            summary = "all ${report.cases.size} regression case(s) compiled and matched",
            artifactPath = report.reportPath.pathString,
        )
    }
}

private fun RepairAssessment.contextHint(): String? = when (this) {
    is RepairAssessment.CompileError -> failure.stdout + "\n" + failure.stderr
    is RepairAssessment.BehaviorError, is RepairAssessment.Valid -> null
}

private fun RepairAssessment.toRequest(
    projectFiles: Map<String, String>,
    regressionInputs: List<ProcessInput>,
): RepairRequest = when (this) {
    is RepairAssessment.CompileError -> RepairRequest(
        failureKind = "compile",
        prompt = failure.toPrompt(),
        projectFiles = projectFiles,
        regressionInputs = regressionInputs,
    )
    is RepairAssessment.BehaviorError -> RepairRequest(
        failureKind = "behavior",
        prompt = diff.toPrompt(),
        projectFiles = projectFiles,
        regressionInputs = regressionInputs,
    )
    is RepairAssessment.Valid -> error("valid projects do not need a repair request")
}

fun StructuredBehaviorDiff.toPrompt(): String = """
    Structured behavior diff for $id:
    ${cases.joinToString("\n") {
        "- ${it.id}: exit expected=${it.exitCodeExpected} actual=${it.exitCodeActual}; " +
            "stdout offset=${it.stdout.firstDifferenceOffset} expected=${it.stdout.expectedHex} actual=${it.stdout.actualHex}; " +
            "stderr offset=${it.stderr.firstDifferenceOffset} expected=${it.stderr.expectedHex} actual=${it.stderr.actualHex}"
    }}
""".trimIndent()

fun StructuredBehaviorDiff.toJson(): String = """
{
  "id": "${id.escapeJson()}",
  "matches": $matches,
  "cases": [
${cases.joinToString(",\n") { it.toJson().prependIndent("    ") }}
  ]
}
""".trimIndent() + "\n"

private fun CaseDiff.toJson(): String = """
{
  "id": "${id.escapeJson()}",
  "args": [${args.joinToString(", ") { "\"${it.escapeJson()}\"" }}],
  "stdinHex": "$stdinHex",
  "matches": $matches,
  "exitCode": {
    "expected": $exitCodeExpected,
    "actual": $exitCodeActual,
    "matches": $exitCodeMatches
  },
  "stdout": ${stdout.toJson()},
  "stderr": ${stderr.toJson()}
}
""".trimIndent()

private fun StreamDiff.toJson(): String = """
{
  "expectedHex": "$expectedHex",
  "actualHex": "$actualHex",
  "firstDifferenceOffset": ${firstDifferenceOffset ?: "null"}
}
""".trimIndent()

private fun RepairIteration.toJson(): String = """
{
  "index": $index,
  "failureKind": "${failureKind.escapeJson()}",
  "prompt": "${prompt.escapeJson()}",
  "summary": "${summary.escapeJson()}",
  "succeeded": $succeeded,
  "retainedRegressionIds": [${retainedRegressionIds.joinToString(", ") { "\"${it.escapeJson()}\"" }}],
  "before": ${before?.toJson() ?: "null"},
  "after": ${after?.toJson() ?: "null"},
  "patches": [
${patches.joinToString(",\n") { it.toJson().prependIndent("    ") }}
  ]
}
""".trimIndent()

private fun RepairEvidence.toJson(): String = """
{
  "kind": "${kind.escapeJson()}",
  "summary": "${summary.escapeJson()}",
  "artifactPath": ${artifactPath?.let { "\"${it.escapeJson()}\"" } ?: "null"}
}
""".trimIndent()

private fun SourcePatch.toJson(): String = """
{
  "relativePath": "${relativePath.escapeJson()}",
  "replacement": "${replacement.escapeJson()}"
}
""".trimIndent()

private fun ProcessInput.toJson(): String = """
{
  "id": "${id.escapeJson()}",
  "args": [${args.joinToString(", ") { "\"${it.escapeJson()}\"" }}],
  "stdinHex": "${stdin.toHex()}"
}
""".trimIndent()

private fun parseProcessInput(element: kotlinx.serialization.json.JsonElement): ProcessInput {
    val value = element.jsonObject
    return ProcessInput(
        id = value.requiredString("id"),
        args = value["args"]?.jsonArray?.map { it.jsonPrimitive.content } ?: emptyList(),
        stdin = value.requiredString("stdinHex").hexToBytes(),
    )
}

private fun parseIteration(element: kotlinx.serialization.json.JsonElement): RepairIteration {
    val value = element.jsonObject
    return RepairIteration(
        index = value["index"]?.jsonPrimitive?.intOrNull ?: error("repair history iteration is missing index"),
        failureKind = value.requiredString("failureKind"),
        prompt = value["prompt"]?.jsonPrimitive?.contentOrNull.orEmpty(),
        summary = value.requiredString("summary"),
        patches = value["patches"]?.jsonArray?.map { patch ->
            val item = patch.jsonObject
            SourcePatch(item.requiredString("relativePath"), item.requiredString("replacement"))
        } ?: emptyList(),
        retainedRegressionIds = value["retainedRegressionIds"]?.jsonArray?.map { it.jsonPrimitive.content } ?: emptyList(),
        before = value["before"]?.let(::parseEvidence),
        after = value["after"]?.let(::parseEvidence),
        succeeded = value["succeeded"]?.jsonPrimitive?.contentOrNull?.toBooleanStrictOrNull() ?: false,
    )
}

private fun parseEvidence(element: kotlinx.serialization.json.JsonElement): RepairEvidence? {
    if (element.toString() == "null") return null
    val value = element.jsonObject
    return RepairEvidence(
        kind = value.requiredString("kind"),
        summary = value.requiredString("summary"),
        artifactPath = value["artifactPath"]?.jsonPrimitive?.contentOrNull,
    )
}

private fun JsonObject.requiredString(name: String): String =
    get(name)?.jsonPrimitive?.contentOrNull ?: error("repair history is missing $name")

private fun String.hexToBytes(): ByteArray {
    require(length % 2 == 0) { "hex input must contain pairs of characters" }
    return ByteArray(length / 2) { index -> substring(index * 2, index * 2 + 2).toInt(16).toByte() }
}

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
