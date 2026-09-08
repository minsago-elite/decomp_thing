package decompengine.project

import decompengine.analysis.GhidraAnalysis
import decompengine.analysis.GhidraJvmAnalyzer
import decompengine.binary.UnresolvedSymbol
import java.io.BufferedInputStream
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.security.MessageDigest
import java.util.Collections
import kotlin.io.path.createDirectories
import kotlin.io.path.pathString
import kotlin.io.path.relativeTo
import kotlin.io.path.writeText

data class BuildReport(
    val projectDir: Path,
    val returnCode: Int,
    val logPath: Path,
    val diagnosticsDir: Path = logPath.parent.resolve("build/modules"),
    val failedOwners: List<String> = emptyList(),
    val command: List<String> = emptyList(),
)

class BuildException(message: String) : RuntimeException(message)

internal data class BuildSourceInput(
    val path: String,
    val bytes: Long,
    val sha256: String,
)

internal data class BuildSourceRevision(
    val sha256: String,
    val inputs: List<BuildSourceInput>,
)

internal data class BuildArtifactIdentity(
    val path: String,
    val bytes: Long,
    val sha256: String,
)

internal fun captureBuildSourceRevision(
    projectDir: Path,
    profile: ReconstructionProfile = GeneratedCMakeReconstructionProfile.descriptor,
): BuildSourceRevision {
    val policy = ReconstructionAdapters.resolve(profile).archiveBuild
    val buildDefinition = profile.layout.declaration("build-definition").materialize()
    val inputs = Files.walk(projectDir).use { paths ->
        paths.filter { path ->
            if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(path)) return@filter false
            val relative = path.relativeTo(projectDir).pathString.replace('\\', '/')
            policy.isBuildInput(profile, relative)
        }.map { path ->
            val relative = path.relativeTo(projectDir).pathString.replace('\\', '/')
            require(relative.isNotBlank() && !relative.startsWith('/') && relative.split('/').none { it in setOf("", ".", "..") }) {
                "build source path is not normalized: $relative"
            }
            val size = Files.size(path)
            BuildSourceInput(relative, size, sha256File(path, size))
        }.toList().sortedBy { it.path }
    }
    require(inputs.isNotEmpty() && inputs.any { it.path == buildDefinition }) {
        "build source revision must contain $buildDefinition and at least one input"
    }
    require(inputs.map { it.path }.distinct().size == inputs.size) { "build source inputs must be unique" }
    val canonical = inputs.joinToString("") { input ->
        "${input.path.length}:${input.path}:${input.bytes}:${input.sha256}\n"
    }
    return BuildSourceRevision(
        sha256(canonical.toByteArray(Charsets.UTF_8)),
        Collections.unmodifiableList(inputs.toList()),
    )
}

internal fun sha256File(path: Path, expectedBytes: Long): String {
    val digest = MessageDigest.getInstance("SHA-256")
    var observedBytes = 0L
    BufferedInputStream(Files.newInputStream(path)).use { input ->
        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            observedBytes = Math.addExact(observedBytes, count.toLong())
            require(observedBytes <= expectedBytes) { "file grew while its build identity was captured: $path" }
            digest.update(buffer, 0, count)
        }
    }
    require(observedBytes == expectedBytes) { "file changed while its build identity was captured: $path" }
    return digest.digest().joinToString("") { "%02x".format(it) }
}

private fun renderUnresolvedReport(analysis: GhidraAnalysis): String {
    val inventory = analysis.symbolInventory
    fun list(symbols: List<UnresolvedSymbol>) = symbols.joinToString(",\n") { it.toJson().prependIndent("      ") }
    return """
    {
      "binary": "${analysis.binaryPath.pathString.escapeJson()}",
      "machine": "${analysis.metadata.machine}",
      "unresolvedFunctionCount": ${inventory.functions.size},
      "unresolvedObjectCount": ${inventory.objects.size},
      "unresolvedOtherCount": ${inventory.other.size},
      "functions": [
        ${list(inventory.functions)}
      ],
      "objects": [
        ${list(inventory.objects)}
      ],
      "other": [
        ${list(inventory.other)}
      ],
      "note": "Unresolved symbols are external imports (libc/runtime) that the reconstructed project depends on but does not define. Their presence does not imply behavioral equivalence."
    }
    """.trimIndent() + "\n"
}

private fun UnresolvedSymbol.toJson(): String = """
{
  "name": "${name.escapeJson()}",
  "kind": "$kind",
  "binding": "$binding",
  "size": $size
}
""".trimIndent()

internal fun String.escapeJson(): String =
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

object RecompilableProjectGenerator {
    fun generate(
        analysis: GhidraAnalysis,
        projectDir: Path,
        reconstructor: ModuleReconstructor = EvidenceModuleReconstructor(),
    ): Path {
        val reportsDir = projectDir.resolve("reports").createDirectories()
        val manifest = SourceTreeGenerator.generate(analysis.programModel, projectDir, reconstructor = reconstructor)
        reportsDir.resolve("analysis.json").writeText(
            """
            {
              "sourceAnalysis": "${analysis.reportPath.pathString}",
              "metadata": {
                "format": "${analysis.metadata.format}",
                "machine": "${analysis.metadata.machine}",
                "entryPoint": ${analysis.metadata.entryPoint}
              },
              "generatedFiles": [
                ${manifest.files.map { it.path }.plus("reports/analysis.json").plus("reports/unresolved.json")
                    .distinct().sorted().joinToString(",\n                ") { "\"$it\"" }}
              ]
            }
            """.trimIndent() + "\n",
        )
        reportsDir.resolve("unresolved.json").writeText(renderUnresolvedReport(analysis))
        return projectDir
    }
}

class ReconstructionPipeline(private val analyzer: GhidraJvmAnalyzer) {
    fun generate(binaryPath: Path, workDir: Path): BuildReport {
        val analysis = analyzer.analyze(binaryPath, workDir.resolve("analysis"))
        val projectDir = RecompilableProjectGenerator.generate(analysis, workDir.resolve("project"))
        return MakeProjectBuilder.build(projectDir)
    }
}
