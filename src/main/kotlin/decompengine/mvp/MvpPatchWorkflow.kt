package decompengine.mvp

import decompengine.repair.RepairClient
import decompengine.repair.RepairRequest
import decompengine.validation.ProcessInput
import java.io.BufferedWriter
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
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
        val work = output.resolve(".work").createDirectories()
        val finalBinary = patchedBinaryDir.resolve("patched_binary")
        finalBinary.deleteIfExists()
        val logger = StreamingLogger(logs.resolve("patch-${Instant.now().toEpochMilli()}.log"))
        var phase = "inspect"
        var patchSummary = "not generated"
        try {
            logger.use {
                it.phase(phase)
                requireElf64(input)
                it.command(listOf("readelf", "-h", "-s", input.pathString), work, "ELF metadata")
                val original = it.command(
                    listOf("timeout", "5s", "stdbuf", "-o0", input.pathString),
                    input.parent,
                    "observe original",
                    requireSuccess = false,
                )
                if (original.stdout.isBlank()) throw MvpPatchException("original produced no observable stdout")

                phase = "reconstruct"
                it.phase(phase)
                val raw = work.resolve("ghidra_decompiled.c")
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

                phase = "compile"
                it.phase(phase)
                val vulnerable = work.resolve("reconstructed_asan")
                compile(it, reconstructed, vulnerable, sanitizer = true, warningsAsErrors = false)

                phase = "reproduce"
                it.phase(phase)
                val finding = it.command(
                    listOf("timeout", "5s", vulnerable.pathString), work, "sanitizer reproducer",
                    environment = mapOf("ASAN_OPTIONS" to "detect_leaks=0:halt_on_error=1"), requireSuccess = false,
                )
                if (finding.exitCode == 0 || !finding.combined.contains("Sanitizer")) {
                    throw MvpPatchException("reconstructed program did not reproduce a sanitizer finding")
                }

                phase = "patch"
                it.phase(phase)
                val proposal = client.requestRepair(
                    RepairRequest(
                        failureKind = "memory-safety",
                        prompt = patchPrompt(original.stdout, finding.combined),
                        projectFiles = mapOf("decompile/decompiled.c" to reconstructed.readText()),
                        regressionInputs = listOf(ProcessInput("default")),
                    ),
                )
                patchSummary = proposal.summary
                val proposedSource = patchedSourceDir.resolve("patched.c")
                proposedSource.writeText(singleReplacement(proposal.patches.map { it.relativePath to it.replacement }, "patched.c"))
                it.command(listOf("diff", "-u", reconstructed.pathString, proposedSource.pathString), work, "proposed patch", false, accepted = setOf(0, 1))
                if (!options.assumeYes && !approve(patchSummary)) throw MvpPatchException("patch was not approved")

                phase = "verify"
                it.phase(phase)
                val patchedAsan = work.resolve("patched_asan")
                compile(it, proposedSource, patchedAsan, sanitizer = true, warningsAsErrors = true)
                verify(it, patchedAsan, original, "sanitizer verification")
                val release = work.resolve("patched_release")
                compile(it, proposedSource, release, sanitizer = false, warningsAsErrors = true)
                verify(it, release, original, "release verification")
                Files.copy(release, finalBinary, StandardCopyOption.REPLACE_EXISTING)
                finalBinary.toFile().setExecutable(true, true)
                writeSummary(summaryDir, input, reconstructed, proposedSource, finalBinary, patchSummary, "PASS", null)
                it.info("completed: $finalBinary")
            }
        } catch (failure: Exception) {
            finalBinary.deleteIfExists()
            writeSummary(summaryDir, input, decompiled.resolve("decompiled.c"), patchedSourceDir.resolve("patched.c"), finalBinary, patchSummary, "FAIL", "$phase: ${failure.message}")
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

    private fun verify(logger: StreamingLogger, binary: Path, expected: CommandResult, label: String) {
        val result = logger.command(listOf("timeout", "5s", binary.pathString), binary.parent, label, false)
        if (result.exitCode != 0 || result.stdout != expected.stdout || result.combined.contains("Sanitizer")) {
            throw MvpPatchException("$label did not preserve observed behavior")
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

private fun promptForApproval(summary: String): Boolean {
    println("Patch summary: $summary"); print("Apply this patch? [y/N] "); System.out.flush()
    return readlnOrNull()?.trim()?.lowercase() in setOf("y", "yes")
}

private fun writeSummary(summaryDir: Path, input: Path, source: Path, patchedSource: Path, binary: Path, patch: String, result: String, failure: String?) {
    summaryDir.createDirectories()
    summaryDir.resolve("SUMMARY.md").writeText("""
        # MVP Patch Summary

        - Result: $result
        - Input SHA-256: `${input.takeIf { it.exists() }?.sha256() ?: "unavailable"}`
        - Decompiled C: `${if (source.exists()) "decompile/decompiled.c" else "unavailable"}`
        - Patched C: `${if (patchedSource.exists()) "patched_c/patched.c" else "unavailable"}`
        - Patched binary: `${if (binary.exists()) "patched_binary/patched_binary" else "not published"}`
        - Failure: ${failure ?: "none"}

        ## Vulnerability Found

        The reconstructed program triggered a memory-safety failure during sanitizer verification before patching. The MVP treats that failure as the evidence used to request and validate the source-level fix.

        ## Patch Explanation

        ${patch.toSummaryParagraph()}

        ## Patched Artifacts

        - Source: `${if (patchedSource.exists()) "patched_c/patched.c" else "unavailable"}`
        - Binary: `${if (binary.exists()) "patched_binary/patched_binary" else "not published"}`

        ## Residual Risk

        This MVP supports small symbol-bearing x86-64 ELF programs and validates only the observed default execution. Input execution is not network-isolated when nested bubblewrap is unavailable.
    """.trimIndent() + "\n")
}

private fun Path.sha256() = MessageDigest.getInstance("SHA-256").digest(readBytes()).joinToString("") { "%02x".format(it) }

private fun String.toSummaryParagraph(): String {
    val normalized = trim().replace(Regex("\\s+"), " ")
    return if (normalized.isBlank() || normalized == "not generated") {
        "No source patch was generated before the workflow stopped."
    } else {
        normalized
    }
}
