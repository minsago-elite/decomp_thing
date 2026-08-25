package decompengine.exploration

import decompengine.validation.ProcessInput
import decompengine.validation.SandboxRunner
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.nio.file.Path
import java.util.Locale
import java.util.concurrent.CompletableFuture
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

data class AngrDiagnostics(
    val argvStates: Int,
    val stdinStates: Int,
    val argvSteps: Int,
    val stdinSteps: Int,
)

interface AngrExplorer {
    val diagnostics: AngrDiagnostics? get() = null
    fun generate(binaryPath: Path): List<CandidateInput>
}

class PythonAngrExplorer(
    private val python: Path = Path.of("/usr/bin/python3"),
    private val timeout: Path = Path.of("/usr/bin/timeout"),
    private val timeoutSeconds: Int = 45,
    private val maxSteps: Int = 300,
    private val maxStates: Int = 64,
    private val argvBytes: Int = 16,
    private val stdinBytes: Int = 32,
) : AngrExplorer {
    override var diagnostics: AngrDiagnostics? = null
        private set

    override fun generate(binaryPath: Path): List<CandidateInput> {
        require(timeoutSeconds > 0 && maxSteps > 0 && maxStates > 0) { "angr exploration bounds must be positive" }
        require(argvBytes > 0 && stdinBytes > 0) { "angr symbolic input sizes must be positive" }
        val command = listOf(
            timeout.pathString,
            "${timeoutSeconds}s",
            python.pathString,
            "-c",
            ANGR_SCRIPT,
            binaryPath.toAbsolutePath().pathString,
            maxSteps.toString(),
            maxStates.toString(),
            argvBytes.toString(),
            stdinBytes.toString(),
        )
        val process = ProcessBuilder(command).start()
        val stdoutFuture = CompletableFuture.supplyAsync { process.inputStream.bufferedReader().readText() }
        val stderrFuture = CompletableFuture.supplyAsync { process.errorStream.bufferedReader().readText() }
        val exitCode = process.waitFor()
        val stdout = stdoutFuture.join()
        val stderr = stderrFuture.join()
        if (exitCode != 0) {
            val reason = if (exitCode == 124) "timed out after ${timeoutSeconds}s" else "failed with exit code $exitCode"
            error("angr candidate generation $reason: ${stderr.ifBlank { stdout }}")
        }
        return parseResult(stdout)
    }

    private fun parseResult(output: String): List<CandidateInput> {
        val root = runCatching { Json.parseToJsonElement(output).jsonObject }
            .getOrElse { error("angr candidate generation returned invalid JSON: ${it.message}") }
        val stats = root["stats"]?.jsonObject ?: error("angr result did not include exploration stats")
        diagnostics = AngrDiagnostics(
            argvStates = stats.requiredInt("argvStates"),
            stdinStates = stats.requiredInt("stdinStates"),
            argvSteps = stats.requiredInt("argvSteps"),
            stdinSteps = stats.requiredInt("stdinSteps"),
        )
        return root["candidates"]?.jsonArray?.map { element ->
            val value = element.jsonObject
            val mode = value.requiredString("mode")
            CandidateInput(
                id = value.requiredString("id"),
                source = CandidateSource.ANGR,
                args = if (mode == "argv") listOf(value.requiredString("argv")) else emptyList(),
                stdin = if (mode == "stdin") value.requiredString("stdinHex").hexToBytes() else ByteArray(0),
            )
        } ?: error("angr result did not include candidates")
    }

    private companion object {
        val ANGR_SCRIPT = """
            import json
            import logging
            import sys

            import angr
            import claripy

            logging.getLogger("angr").setLevel(logging.ERROR)
            logging.getLogger("cle").setLevel(logging.ERROR)

            binary, max_steps, max_states, argv_size, stdin_size = sys.argv[1:]
            max_steps = int(max_steps)
            max_states = int(max_states)
            argv_size = int(argv_size)
            stdin_size = int(stdin_size)
            project = angr.Project(binary, auto_load_libs=False)

            def constrain_bytes(state, byte_values, allow_newline):
                for value in byte_values:
                    choices = [claripy.And(value >= 0x20, value <= 0x7e), value == 0]
                    if allow_newline:
                        choices.append(value == 0x0a)
                    state.solver.add(claripy.Or(*choices))
                for index in range(len(byte_values) - 1):
                    state.solver.add(claripy.Or(byte_values[index] != 0, byte_values[index + 1] == 0))

            def execute(state):
                manager = project.factory.simgr(state)
                steps = 0
                while manager.active and steps < max_steps:
                    manager.step()
                    steps += 1
                    if len(manager.active) > max_states:
                        manager.stashes["active"] = manager.active[:max_states]
                states = manager.deadended + manager.active
                return states[:max_states], steps

            def signature(state):
                return (
                    state.posix.dumps(1).hex(),
                    state.posix.dumps(2).hex(),
                    state.addr,
                )

            candidates = []
            seen = set()

            argv_values = [claripy.BVS("argv_%d" % index, 8) for index in range(argv_size)]
            argv_symbol = claripy.Concat(*argv_values)
            argv_state = project.factory.entry_state(args=[binary, argv_symbol])
            constrain_bytes(argv_state, argv_values, False)
            argv_states, argv_steps = execute(argv_state)
            for state in argv_states:
                concrete = state.solver.eval(argv_symbol, cast_to=bytes).split(b"\x00", 1)[0]
                if not concrete:
                    continue
                key = ("argv", concrete, signature(state))
                if key in seen:
                    continue
                seen.add(key)
                candidates.append({
                    "id": "angr_argv_%d" % len(candidates),
                    "mode": "argv",
                    "argv": concrete.decode("utf-8", "replace"),
                    "stdinHex": "",
                })

            stdin_values = [claripy.BVS("stdin_%d" % index, 8) for index in range(stdin_size)]
            stdin_symbol = claripy.Concat(*stdin_values)

            class ControlledFgets(angr.SimProcedure):
                def run(self, destination, size, stream):
                    maximum = self.state.solver.eval(size)
                    count = min(stdin_size, max(0, maximum - 1))
                    self.state.memory.store(destination, stdin_symbol.get_bytes(0, count))
                    self.state.memory.store(destination + count, claripy.BVV(0, 8))
                    return destination

            fgets_symbol = project.loader.find_symbol("fgets")
            if fgets_symbol is not None:
                project.hook(fgets_symbol.rebased_addr, ControlledFgets(), replace=True)
            stdin_file = angr.SimFileStream(name="stdin", content=stdin_symbol, has_end=True)
            stdin_state = project.factory.entry_state(
                args=[binary],
                stdin=stdin_file,
                add_options={
                    angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
                },
            )
            constrain_bytes(stdin_state, stdin_values, True)
            stdin_states, stdin_steps = execute(stdin_state)
            for state in stdin_states:
                concrete = state.solver.eval(stdin_symbol, cast_to=bytes).rstrip(b"\x00")
                if not concrete:
                    continue
                key = ("stdin", concrete, signature(state))
                if key in seen:
                    continue
                seen.add(key)
                candidates.append({
                    "id": "angr_stdin_%d" % len(candidates),
                    "mode": "stdin",
                    "argv": "",
                    "stdinHex": concrete.hex(),
                })

            print(json.dumps({
                "stats": {
                    "argvStates": len(argv_states),
                    "stdinStates": len(stdin_states),
                    "argvSteps": argv_steps,
                    "stdinSteps": stdin_steps,
                },
                "candidates": candidates,
            }, separators=(",", ":")))
        """.trimIndent()
    }
}

class StaticHintGenerator(
    private val stringsPath: Path = Path.of("/usr/bin/strings"),
    private val maxHints: Int = 64,
) {
    fun generate(binaryPath: Path): List<CandidateInput> {
        val process = ProcessBuilder(stringsPath.pathString, "-a", "-n", "3", binaryPath.pathString)
            .redirectErrorStream(true)
            .start()
        val output = process.inputStream.bufferedReader().readText()
        val exitCode = process.waitFor()
        if (exitCode != 0) error("strings failed with exit code $exitCode: $output")
        val hints = output.lineSequence()
            .map(String::trim)
            .filter { it.length in 3..80 }
            .filter { hint -> hint.all { it == '\t' || it in ' '..'~' } && hint.any(Char::isLetterOrDigit) }
            .distinct()
            .sortedWith(compareBy<String>({ staticHintPriority(it) }, { it.length }, { it }))
            .take(maxHints)
            .toList()
        return hints.flatMapIndexed { index, hint ->
            listOf(
                CandidateInput("static_arg_$index", CandidateSource.STATIC_HINT, args = listOf(hint)),
                CandidateInput("static_stdin_$index", CandidateSource.STATIC_HINT, stdin = "$hint\n".toByteArray()),
            )
        }
    }

    private fun staticHintPriority(hint: String): Int = when {
        hint.matches(Regex("[A-Za-z0-9_./:@+-]+")) -> 0
        hint.contains("%s") || hint.contains("%d") -> 2
        else -> 1
    }
}

class MutationExpander(private val maxMutations: Int = 256) {
    fun expand(seeds: List<CandidateInput>): List<CandidateInput> =
        seeds.asSequence().flatMap { seed -> mutate(seed).asSequence() }
            .distinctBy(CandidateInput::contentKey)
            .take(maxMutations)
            .toList()

    private fun mutate(seed: CandidateInput): List<CandidateInput> {
        val stdinText = seed.stdin.decodeToString()
        val args = seed.args
        val candidates = mutableListOf<CandidateInput>()
        fun add(suffix: String, mutatedArgs: List<String> = args, mutatedStdin: String = stdinText) {
            if (mutatedArgs != args || mutatedStdin != stdinText) {
                candidates += CandidateInput("${seed.id}_$suffix", CandidateSource.MUTATION, mutatedArgs, mutatedStdin.toByteArray())
            }
        }
        add("upper", args.map(String::uppercase), stdinText.uppercase())
        add("lower", args.map(String::lowercase), stdinText.lowercase())
        add("double", args.map { it + it }, stdinText + stdinText)
        add("empty", emptyList(), "")
        add("newline", args, if (stdinText.endsWith("\n")) stdinText.dropLast(1) else "$stdinText\n")
        listOf(1, 8, 16, 32, 64, 128, 256).forEach { size ->
            add("boundary_$size", args.map { it.take(size).padEnd(size, 'A') }, stdinText.take(size).padEnd(size, 'A'))
        }
        return candidates
    }
}

data class CandidateObservation(
    val candidateId: String,
    val signature: String,
    val exitCode: Int,
    val stdoutHex: String,
    val stderrHex: String,
    val networkIsolated: Boolean,
)

data class CoverageReport(
    val baselineCount: Int,
    val expandedCount: Int,
    val baselineSignatures: Set<String>,
    val expandedSignatures: Set<String>,
    val observations: List<CandidateObservation> = emptyList(),
) {
    val newSignatures: Set<String> = expandedSignatures - baselineSignatures
    val increased: Boolean = newSignatures.isNotEmpty()
    val networkIsolated: Boolean = observations.isNotEmpty() && observations.all { it.networkIsolated }
}

class OutputCoverageMeasurer(private val sandbox: SandboxRunner = SandboxRunner()) {
    fun measure(binaryPath: Path, baseline: List<CandidateInput>, expanded: List<CandidateInput>): CoverageReport {
        val baselineObservations = observe(binaryPath, baseline)
        val expandedObservations = observe(binaryPath, expanded)
        return CoverageReport(
            baselineCount = baseline.size,
            expandedCount = expanded.size,
            baselineSignatures = baselineObservations.map { it.signature }.toSet(),
            expandedSignatures = expandedObservations.map { it.signature }.toSet(),
            observations = expandedObservations,
        )
    }

    private fun observe(binaryPath: Path, inputs: List<CandidateInput>): List<CandidateObservation> = inputs.map { candidate ->
        val output = sandbox.run(binaryPath, candidate.toProcessInput())
        val stdoutHex = output.stdout.toHex()
        val stderrHex = output.stderr.toHex()
        CandidateObservation(
            candidateId = candidate.id,
            signature = "${output.exitCode}:$stdoutHex:$stderrHex",
            exitCode = output.exitCode,
            stdoutHex = stdoutHex,
            stderrHex = stderrHex,
            networkIsolated = output.networkIsolated,
        )
    }
}

data class ConfidenceScore(
    val score: Double,
    val inputCount: Int,
    val sourceCount: Int,
    val outputSignatureCount: Int,
    val sandboxed: Boolean,
    val newOutputSignatureCount: Int = 0,
    val networkIsolated: Boolean = false,
)

object ConfidenceScorer {
    fun score(inputs: List<CandidateInput>, coverage: CoverageReport, sandboxed: Boolean): ConfidenceScore {
        val sourceCount = inputs.map { it.source }.toSet().size
        val breadth = (inputs.size.coerceAtMost(24) / 24.0) * 0.30
        val sourceBreadth = (sourceCount.coerceAtMost(4) / 4.0) * 0.20
        val outputBreadth = (coverage.expandedSignatures.size.coerceAtMost(8) / 8.0) * 0.25
        val discoveryBreadth = (coverage.newSignatures.size.coerceAtMost(4) / 4.0) * 0.15
        val sandboxScore = if (sandboxed) 0.05 else 0.0
        val networkScore = if (coverage.networkIsolated) 0.05 else 0.0
        return ConfidenceScore(
            score = breadth + sourceBreadth + outputBreadth + discoveryBreadth + sandboxScore + networkScore,
            inputCount = inputs.size,
            sourceCount = sourceCount,
            outputSignatureCount = coverage.expandedSignatures.size,
            sandboxed = sandboxed,
            newOutputSignatureCount = coverage.newSignatures.size,
            networkIsolated = coverage.networkIsolated,
        )
    }
}

data class ExplorationReport(
    val candidates: List<CandidateInput>,
    val coverage: CoverageReport,
    val confidence: ConfidenceScore,
    val reportPath: Path,
    val angrDiagnostics: AngrDiagnostics? = null,
)

class AutomaticExplorer(
    private val angrExplorer: AngrExplorer = PythonAngrExplorer(),
    private val staticHints: StaticHintGenerator = StaticHintGenerator(),
    private val mutations: MutationExpander = MutationExpander(),
    private val coverage: OutputCoverageMeasurer = OutputCoverageMeasurer(),
    private val maxCandidates: Int = 192,
) {
    fun explore(binaryPath: Path, seedInputs: List<CandidateInput>, reportsDir: Path): ExplorationReport {
        require(seedInputs.isNotEmpty()) { "at least one seed input is required" }
        val generated = seedInputs + angrExplorer.generate(binaryPath) + staticHints.generate(binaryPath)
        val expanded = (generated + mutations.expand(generated))
            .distinctBy(CandidateInput::contentKey)
            .take(maxCandidates)
        val coverageReport = coverage.measure(binaryPath, seedInputs, expanded)
        val confidence = ConfidenceScorer.score(expanded, coverageReport, sandboxed = true)
        val reportPath = reportsDir.createDirectories().resolve("exploration.json")
        val report = ExplorationReport(expanded, coverageReport, confidence, reportPath, angrExplorer.diagnostics)
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
  "newOutputSignatures": [${coverage.newSignatures.sorted().joinToString(", ") { "\"${it.escapeJson()}\"" }}],
  "angr": ${angrDiagnostics?.toJson() ?: "null"},
  "confidence": {
    "score": ${String.format(Locale.ROOT, "%.4f", confidence.score)},
    "inputCount": ${confidence.inputCount},
    "sourceCount": ${confidence.sourceCount},
    "outputSignatureCount": ${confidence.outputSignatureCount},
    "newOutputSignatureCount": ${confidence.newOutputSignatureCount},
    "sandboxed": ${confidence.sandboxed},
    "networkIsolated": ${confidence.networkIsolated}
  },
  "candidates": [
${candidates.joinToString(",\n") { it.toJson().prependIndent("    ") }}
  ],
  "observations": [
${coverage.observations.joinToString(",\n") { it.toJson().prependIndent("    ") }}
  ]
}
""".trimIndent() + "\n"

private fun AngrDiagnostics.toJson(): String = """
{
  "argvStates": $argvStates,
  "stdinStates": $stdinStates,
  "argvSteps": $argvSteps,
  "stdinSteps": $stdinSteps
}
""".trimIndent()

private fun CandidateInput.toJson(): String = """
{
  "id": "${id.escapeJson()}",
  "source": "$source",
  "args": [${args.joinToString(", ") { "\"${it.escapeJson()}\"" }}],
  "stdinHex": "${stdin.toHex()}"
}
""".trimIndent()

private fun CandidateObservation.toJson(): String = """
{
  "candidateId": "${candidateId.escapeJson()}",
  "signature": "${signature.escapeJson()}",
  "exitCode": $exitCode,
  "stdoutHex": "$stdoutHex",
  "stderrHex": "$stderrHex",
  "networkIsolated": $networkIsolated
}
""".trimIndent()

private fun CandidateInput.contentKey(): String =
    args.joinToString("\u0000") + "\u0001" + stdin.toHex()

private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

private fun String.hexToBytes(): ByteArray {
    require(length % 2 == 0) { "hex input must contain pairs of characters" }
    return ByteArray(length / 2) { index -> substring(index * 2, index * 2 + 2).toInt(16).toByte() }
}

private fun kotlinx.serialization.json.JsonObject.requiredString(name: String): String =
    get(name)?.jsonPrimitive?.contentOrNull ?: error("angr result is missing $name")

private fun kotlinx.serialization.json.JsonObject.requiredInt(name: String): Int =
    get(name)?.jsonPrimitive?.intOrNull ?: error("angr result is missing $name")

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
