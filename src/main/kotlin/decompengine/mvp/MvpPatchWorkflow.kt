package decompengine.mvp

import decompengine.repair.RepairClient
import decompengine.repair.RepairRequest
import decompengine.validation.ProcessInput
import java.io.BufferedWriter
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.time.Instant
import java.util.Comparator
import kotlin.io.path.createDirectories
import kotlin.io.path.deleteIfExists
import kotlin.io.path.exists
import kotlin.io.path.isRegularFile
import kotlin.io.path.pathString
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.io.path.writeText

data class MvpPatchOptions(val inputElf: Path, val outputDir: Path, val assumeYes: Boolean = false)
class MvpPatchException(message: String) : RuntimeException(message)

class MvpPatchWorkflow(
    private val client: RepairClient,
    private val environment: Map<String, String> = System.getenv(),
    private val approve: (String) -> Boolean = ::promptForApproval,
    private val decompiler: BinaryDecompiler = GhidraDecompiler(environment),
    private val binaryExecution: BinaryExecutionBoundary = BinaryExecutionBoundaryFactory.fromEnvironment(environment),
) {
    fun run(options: MvpPatchOptions) {
        val input = options.inputElf.toAbsolutePath().normalize()
        val output = options.outputDir.toAbsolutePath().normalize()
        require(input.isRegularFile()) { "input ELF does not exist: $input" }
        cleanOutputDirectory(output, input)
        val logs = output.resolve("logs").createDirectories()
        val decompiled = output.resolve("decompile").createDirectories()
        val patchedSourceDir = output.resolve("patched_c").createDirectories()
        val patchedBinaryDir = output.resolve("patched_binary").createDirectories()
        val summaryDir = output.resolve("summary").createDirectories()
        val evidenceDir = output.resolve("evidence").createDirectories()
        val work = output.resolve(".work").createDirectories()
        val raw = work.resolve("ghidra_decompiled.c")
        val finalBinary = patchedBinaryDir.resolve("patched_binary")
        finalBinary.deleteIfExists()
        val logger = StreamingLogger(logs.resolve("patch-${Instant.now().toEpochMilli()}.log"))
        val evidence = MvpRunEvidence(environment)
        var phase = "inspect"
        try {
            logger.use {
                evidence.startPhase(phase)
                it.phase(phase)
                requireElf64(input)
                it.command(listOf("readelf", "-h", "-s", input.pathString), work, "ELF metadata")
                val original = it.binary(binaryExecution, input, input.parent, "observe original")
                evidence.isolation = original.isolation.requireSecure().toString()
                if (original.stdout.isBlank()) throw MvpPatchException("original produced no observable stdout")
                evidence.check("original behavior observation", original.exitCode == 0, "exit=${original.exitCode}, stdoutBytes=${original.stdout.toByteArray().size}")
                evidence.passPhase(phase, "ELF metadata inspected and default behavior retained")

                phase = "reconstruct"
                evidence.startPhase(phase)
                it.phase(phase)
                decompiler.decompile(it, input, work, raw)
                if (!raw.exists() || raw.readText().isBlank()) throw MvpPatchException("Ghidra produced no decompiler output")
                val reconstructed = decompiled.resolve("decompiled.c")
                val reconstruction = client.requestRepair(
                    RepairRequest(
                        failureKind = "binary-reconstruction",
                        prompt = reconstructionPrompt(original.stdout),
                        projectFiles = mapOf("ghidra_decompiled.c" to raw.readText()),
                        regressionInputs = listOf(ProcessInput("default")),
                    ),
                )
                reconstructed.writeText(singleReplacement(reconstruction.patches.map { it.relativePath to it.replacement }, "decompiled.c"))
                evidence.passPhase(phase, "Ghidra export converted to standalone decompile/decompiled.c")

                phase = "compile"
                evidence.startPhase(phase)
                it.phase(phase)
                val vulnerable = work.resolve("reconstructed_asan")
                compile(it, reconstructed, vulnerable, sanitizer = true, warningsAsErrors = false)
                evidence.check("reconstructed sanitizer build", true, "compiled with AddressSanitizer and UBSan")
                evidence.passPhase(phase, "reconstructed source compiled with sanitizers")

                phase = "reproduce"
                evidence.startPhase(phase)
                it.phase(phase)
                val finding = it.binary(
                    binaryExecution, vulnerable, work, "sanitizer reproducer",
                    environment = mapOf("ASAN_OPTIONS" to "detect_leaks=0:halt_on_error=1"),
                )
                if (finding.exitCode == 0 || !finding.combined.contains("Sanitizer")) {
                    throw MvpPatchException("reconstructed program did not reproduce a sanitizer finding")
                }
                val findingPath = evidenceDir.resolve("cwe-787-sanitizer.txt")
                findingPath.writeText(evidence.redact(finding.combined))
                evidence.findingPath = findingPath
                evidence.findingSourceLocation = findSourceLocation(finding.combined)
                    ?: throw MvpPatchException("sanitizer finding did not map to decompile/decompiled.c")
                evidence.check("CWE-787 reproduction", true, "out-of-bounds write retained at ${evidence.findingSourceLocation}; exit=${finding.exitCode}")
                evidence.passPhase(phase, "CWE-787 sanitizer failure reproduced and mapped to reconstructed C")

                phase = "patch"
                evidence.startPhase(phase)
                it.phase(phase)
                val proposal = client.requestRepair(
                    RepairRequest(
                        failureKind = "memory-safety",
                        prompt = patchPrompt(original.stdout, finding.combined),
                        projectFiles = mapOf("decompile/decompiled.c" to reconstructed.readText()),
                        regressionInputs = listOf(ProcessInput("default")),
                    ),
                )
                evidence.patchExplanation = proposal.summary
                val proposedSource = patchedSourceDir.resolve("patched.c")
                proposedSource.writeText(singleReplacement(proposal.patches.map { it.relativePath to it.replacement }, "patched.c"))
                val diff = it.command(listOf("diff", "-u", reconstructed.pathString, proposedSource.pathString), work, "proposed patch", false, accepted = setOf(0, 1))
                if (diff.exitCode == 0 || diff.stdout.isBlank()) throw MvpPatchException("proposed patch did not change reconstructed C")
                val diffPath = evidenceDir.resolve("approved.patch")
                diffPath.writeText(evidence.redact(diff.stdout))
                evidence.patchDiff = diff.stdout
                evidence.patchDiffPath = diffPath
                val approved = options.assumeYes || approve(evidence.patchExplanation)
                evidence.approvalDecision = when {
                    !approved -> "rejected interactively"
                    options.assumeYes -> "approved by --yes automation"
                    else -> "approved interactively"
                }
                evidence.check("source patch approval", approved, evidence.approvalDecision)
                if (!approved) throw MvpPatchException("patch was not approved")
                evidence.passPhase(phase, "non-empty source diff approved and retained at evidence/approved.patch")

                phase = "verify"
                evidence.startPhase(phase)
                it.phase(phase)
                val patchedAsan = work.resolve("patched_asan")
                compile(it, proposedSource, patchedAsan, sanitizer = true, warningsAsErrors = true)
                evidence.check("patched sanitizer build", true, "compiled with -Werror, AddressSanitizer, and UBSan")
                verify(it, patchedAsan, original, "sanitizer security validation")
                evidence.check("sanitizer security validation", true, "CWE-787 reproducer no longer reports a sanitizer failure")
                val release = work.resolve("patched_release")
                compile(it, proposedSource, release, sanitizer = false, warningsAsErrors = true)
                evidence.check("hardened release build", true, "compiled with FORTIFY_SOURCE=2, stack protector, PIE, RELRO, and immediate binding")
                verifyHardening(it, release)
                evidence.check("binary hardening inspection", true, "ELF is PIE with GNU_RELRO and immediate binding")
                verify(it, release, original, "release verification")
                evidence.check("behavior validation", true, "exit code and stdout match the observed original default execution")
                Files.copy(release, finalBinary, StandardCopyOption.REPLACE_EXISTING)
                finalBinary.toFile().setExecutable(true, true)
                evidence.passPhase(phase, "all sanitizer, hardening, security, and behavior checks passed")
                writeMvpSummary(summaryDir.resolve("SUMMARY.md"), output, input, raw, reconstructed, proposedSource, finalBinary, "PASS", null, evidence)
                it.info("completed: $finalBinary")
            }
        } catch (failure: Exception) {
            finalBinary.deleteIfExists()
            evidence.failPhase(phase, failure.message ?: failure.javaClass.simpleName)
            writeMvpSummary(
                summaryDir.resolve("SUMMARY.md"), output, input, raw, decompiled.resolve("decompiled.c"),
                patchedSourceDir.resolve("patched.c"), finalBinary, "FAIL", "$phase: ${failure.message}", evidence,
            )
            throw if (failure is MvpPatchException) failure else MvpPatchException(failure.message ?: failure.javaClass.simpleName)
        }
    }

    private fun compile(logger: StreamingLogger, source: Path, target: Path, sanitizer: Boolean, warningsAsErrors: Boolean) {
        val command = mutableListOf("gcc", "-std=c11", "-O1", "-g", "-Wall", "-Wextra")
        if (warningsAsErrors) command += "-Werror"
        if (sanitizer) command += listOf("-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=0", "-fsanitize=address,undefined", "-fno-omit-frame-pointer")
        else command += listOf("-D_FORTIFY_SOURCE=2", "-fstack-protector-strong", "-fPIE", "-pie", "-Wl,-z,relro,-z,now")
        command += listOf(source.pathString, "-o", target.pathString)
        logger.command(command, target.parent, "compile ${target.fileName}")
    }

    private fun verify(logger: StreamingLogger, binary: Path, expected: BinaryExecutionResult, label: String) {
        val result = logger.binary(binaryExecution, binary, binary.parent, label)
        if (result.exitCode != 0 || result.stdout != expected.stdout || result.combined.contains("Sanitizer")) {
            throw MvpPatchException("$label did not preserve observed behavior")
        }
    }

    private fun verifyHardening(logger: StreamingLogger, binary: Path) {
        val headers = logger.command(listOf("readelf", "-W", "-h", "-l", "-d", binary.pathString), binary.parent, "hardening inspection")
        val output = headers.combined
        if (!Regex("Type:\\s+DYN").containsMatchIn(output) || !output.contains("GNU_RELRO") ||
            !(output.contains("BIND_NOW") || Regex("FLAGS.*NOW").containsMatchIn(output))
        ) {
            throw MvpPatchException("release binary is missing required PIE, RELRO, or immediate-binding hardening")
        }
    }
}

private fun cleanOutputDirectory(output: Path, input: Path) {
    require(output.root == null || output != output.root) { "refusing to clean unsafe output directory: $output" }
    require(output != input.parent) { "refusing to clean input parent directory: $output" }
    if (!output.exists()) return
    Files.walk(output).use { paths ->
        paths.sorted(Comparator.reverseOrder()).forEach { path ->
            if (path != output) Files.deleteIfExists(path)
        }
    }
}

fun interface BinaryDecompiler {
    fun decompile(logger: StreamingLogger, input: Path, work: Path, raw: Path)
}

class GhidraDecompiler(private val environment: Map<String, String> = System.getenv()) : BinaryDecompiler {
    override fun decompile(logger: StreamingLogger, input: Path, work: Path, raw: Path) {
        val ghidra = environment["GHIDRA_HOME"]?.let(Path::of)
            ?: throw MvpPatchException("GHIDRA_HOME is required")
        val scripts = work.resolve("ghidra_scripts").createDirectories()
        javaClass.getResourceAsStream("/ghidra_scripts/ExportDecompiledC.java")?.use {
            Files.copy(it, scripts.resolve("ExportDecompiledC.java"), StandardCopyOption.REPLACE_EXISTING)
        } ?: throw MvpPatchException("bundled Ghidra script is missing")
        val projectDir = work.resolve("ghidra_project").createDirectories()
        logger.command(
            listOf(
                ghidra.resolve("support/analyzeHeadless").pathString,
                projectDir.pathString, "mvp", "-import", input.pathString, "-overwrite",
                "-scriptPath", scripts.pathString, "-postScript", "ExportDecompiledC.java", raw.pathString,
            ), work, "Ghidra decompile",
        )
    }
}

data class CommandResult(val exitCode: Int, val stdout: String, val stderr: String) {
    val combined: String = stdout + stderr
}

class StreamingLogger(path: Path) : AutoCloseable {
    private val writer: BufferedWriter = Files.newBufferedWriter(path)
    fun phase(name: String) = info("==> $name")
    fun info(message: String) {
        println(message); System.out.flush(); writer.appendLine("[${Instant.now()}] $message"); writer.flush()
    }
    fun command(
        command: List<String>, directory: Path, label: String, requireSuccess: Boolean = true,
        environment: Map<String, String> = emptyMap(), accepted: Set<Int> = setOf(0),
    ): CommandResult {
        info("$ $label: ${command.joinToString(" ")}")
        val process = ProcessBuilder(command).directory(directory.toFile())
            .apply { environment().putAll(environment) }.start()
        val stdout = StringBuilder()
        val stderr = StringBuilder()
        val outThread = stream(process.inputStream, stdout, false)
        val errThread = stream(process.errorStream, stderr, true)
        outThread.join(); errThread.join()
        val code = process.waitFor(); info("$label exit_code=$code")
        if (requireSuccess && code !in accepted) throw MvpPatchException("$label failed with exit code $code")
        return CommandResult(code, stdout.toString(), stderr.toString())
    }

    fun binary(
        boundary: BinaryExecutionBoundary,
        executable: Path,
        directory: Path,
        label: String,
        environment: Map<String, String> = emptyMap(),
    ): BinaryExecutionResult {
        info("$ $label: isolated-exec ${executable.toAbsolutePath().normalize()}")
        val result = boundary.execute(executable, directory, environment)
        synchronized(this) {
            result.stdout.lineSequence().filter(String::isNotEmpty).forEach { line -> println(line); writer.appendLine(line) }
            result.stderr.lineSequence().filter(String::isNotEmpty).forEach { line -> System.err.println(line); writer.appendLine("[stderr] $line") }
            writer.flush()
        }
        info("$label exit_code=${result.exitCode} isolation=${result.isolation}")
        return result
    }

    private fun stream(input: java.io.InputStream, capture: StringBuilder, error: Boolean): Thread =
        Thread {
            input.bufferedReader().useLines { lines -> lines.forEach { line ->
                synchronized(this) {
                    capture.appendLine(line)
                    if (error) System.err.println(line) else println(line)
                    if (error) System.err.flush() else System.out.flush()
                    writer.appendLine(if (error) "[stderr] $line" else line); writer.flush()
                }
            } }
        }.also { it.start() }
    override fun close() = writer.close()
}

private fun singleReplacement(patches: List<Pair<String, String>>, suffix: String): String {
    if (patches.size != 1 || !patches.single().first.endsWith(suffix)) {
        throw MvpPatchException("API must return exactly one full reconstructed.c replacement")
    }
    return patches.single().second.removeSurrounding("```c\n", "\n```")
}

private fun requireElf64(path: Path) {
    val bytes = path.readBytes()
    val magic = byteArrayOf(0x7f, 0x45, 0x4c, 0x46)
    if (bytes.size < 5 || !bytes.copyOfRange(0, 4).contentEquals(magic) || bytes[4].toInt() != 2) {
        throw MvpPatchException("only 64-bit ELF input is supported")
    }
}

private fun reconstructionPrompt(stdout: String) = """
    Convert the Ghidra decompiler output into one standalone, readable C11 source file with main.
    Preserve the observed default execution exactly. Observed combined output:\n$stdout
    Preserve suspicious memory operations as reconstructed; do not fix vulnerabilities yet.
    Resolve Ghidra types, labels, wrappers, and string references into normal C. Do not invent extra behavior.
    Return exactly one full-file replacement whose relativePath is decompiled.c.
""".trimIndent()

private fun patchPrompt(stdout: String, sanitizer: String) = """
    Apply the smallest clear memory-safety fix to the supplied reconstructed C.
    Preserve observed output exactly:\n$stdout
    Sanitizer evidence:\n$sanitizer
    Return exactly one full-file replacement whose relativePath is patched.c. It must compile as C11 with -Wall -Wextra -Werror.
    In the JSON summary, explain the vulnerability root cause, the exact code change, and why the change preserves observed behavior.
""".trimIndent()

private fun findSourceLocation(sanitizer: String): String? =
    Regex("(?:[A-Za-z]:)?[^\\s:]*decompiled\\.c:\\d+(?::\\d+)?")
        .find(sanitizer)
        ?.value
        ?.substringAfterLast('/')

private fun promptForApproval(summary: String): Boolean {
    println("Patch summary: $summary"); print("Apply this patch? [y/N] "); System.out.flush()
    return readlnOrNull()?.trim()?.lowercase() in setOf("y", "yes")
}
