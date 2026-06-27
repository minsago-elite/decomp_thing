package decompengine.analysis

import decompengine.binary.ElfMetadata
import decompengine.binary.ElfMetadataReader
import decompengine.binary.ElfSymbolInventoryReader
import decompengine.binary.SymbolInventory

import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.net.URLClassLoader
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.pathString
import kotlin.io.path.readBytes
import kotlin.io.path.writeText

data class GhidraJvmConfig(
    val classpath: List<Path>,
    val mainClass: String = "ghidra.app.util.headless.AnalyzeHeadless",
)

data class GhidraAnalysis(
    val binaryPath: Path,
    val reportsDir: Path,
    val metadata: ElfMetadata,
    val symbolInventory: SymbolInventory,
    val mainClass: String,
    val args: List<String>,
    val returnCode: Int,
) {
    val reportPath: Path = reportsDir.resolve("ghidra_analysis.json")
}

class GhidraAnalysisException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)

class GhidraJvmAnalyzer(private val config: GhidraJvmConfig) {
    fun analyze(binaryPath: Path, outputDir: Path): GhidraAnalysis {
        val reportsDir = outputDir.resolve("reports").createDirectories()
        val ghidraProjectDir = outputDir.resolve("ghidra_project").createDirectories()
        val args = listOf(
            ghidraProjectDir.pathString,
            "decomp_engine_l1",
            "-import",
            binaryPath.pathString,
            "-overwrite",
        )

        val stdout = ByteArrayOutputStream()
        val stderr = ByteArrayOutputStream()
        val returnCode = captureOutput(stdout, stderr) {
            invokeMain(args.toTypedArray())
        }

        reportsDir.resolve("ghidra_stdout.log").writeText(stdout.toString(Charsets.UTF_8))
        reportsDir.resolve("ghidra_stderr.log").writeText(stderr.toString(Charsets.UTF_8))

        val binaryBytes = binaryPath.readBytes()
        val metadata = ElfMetadataReader.read(binaryBytes)
        val analysis = GhidraAnalysis(
            binaryPath = binaryPath,
            reportsDir = reportsDir,
            metadata = metadata,
            symbolInventory = ElfSymbolInventoryReader.read(binaryBytes, metadata),
            mainClass = config.mainClass,
            args = args,
            returnCode = returnCode,
        )
        analysis.reportPath.writeText(analysis.toJson())
        if (returnCode != 0) {
            throw GhidraAnalysisException("Ghidra JVM analysis failed with exit code $returnCode")
        }
        return analysis
    }

    private fun invokeMain(args: Array<String>): Int {
        val urls = config.classpath.map { it.toUri().toURL() }.toTypedArray()
        URLClassLoader(urls, javaClass.classLoader).use { loader ->
            val klass = Class.forName(config.mainClass, true, loader)
            val main = klass.getMethod("main", Array<String>::class.java)
            try {
                main.invoke(null, args)
            } catch (exception: java.lang.reflect.InvocationTargetException) {
                val cause = exception.cause ?: exception
                if (cause is SecurityException) throw cause
                throw GhidraAnalysisException("Ghidra main invocation failed", cause)
            }
        }
        return 0
    }

    private fun captureOutput(stdout: ByteArrayOutputStream, stderr: ByteArrayOutputStream, block: () -> Int): Int {
        val previousOut = System.out
        val previousErr = System.err
        return try {
            PrintStream(stdout, true, Charsets.UTF_8).use { out ->
                PrintStream(stderr, true, Charsets.UTF_8).use { err ->
                    System.setOut(out)
                    System.setErr(err)
                    block()
                }
            }
        } finally {
            System.setOut(previousOut)
            System.setErr(previousErr)
        }
    }
}

private fun GhidraAnalysis.toJson(): String = """
{
  "tool": "ghidra-jvm",
  "mainClass": "${mainClass.escapeJson()}",
  "returnCode": $returnCode,
  "binary": "${binaryPath.pathString.escapeJson()}",
  "args": [${args.joinToString(", ") { "\"${it.escapeJson()}\"" }}],
  "metadata": {
    "format": "${metadata.format}",
    "endianness": "${metadata.endianness}",
    "elfVersion": ${metadata.elfVersion},
    "osAbi": "${metadata.osAbi}",
    "objectType": "${metadata.objectType}",
    "machine": "${metadata.machine}",
    "entryPoint": ${metadata.entryPoint},
    "elfHeaderSize": ${metadata.elfHeaderSize},
    "programHeaderCount": ${metadata.programHeaderCount},
    "sectionHeaderCount": ${metadata.sectionHeaderCount},
    "sectionNameTableIndex": ${metadata.sectionNameTableIndex}
  },
  "stdoutLog": "${reportsDir.resolve("ghidra_stdout.log").pathString.escapeJson()}",
  "stderrLog": "${reportsDir.resolve("ghidra_stderr.log").pathString.escapeJson()}"
}
""".trimIndent() + "\n"

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
