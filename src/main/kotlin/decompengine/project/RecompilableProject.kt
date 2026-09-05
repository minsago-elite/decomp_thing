package decompengine.project

import decompengine.analysis.GhidraAnalysis
import decompengine.analysis.GhidraJvmAnalyzer
import decompengine.binary.UnresolvedSymbol
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.BufferedInputStream
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.security.MessageDigest
import java.util.Collections
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletionException
import java.util.concurrent.TimeUnit
import kotlin.io.path.createDirectories
import kotlin.io.path.exists
import kotlin.io.path.isRegularFile
import kotlin.io.path.pathString
import kotlin.io.path.readText
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

data class ProjectBuildConfiguration(
    val makeExecutable: String = "make",
    val compilerExecutable: String = "gcc",
    val parallelism: Int = 4,
    val cFlags: List<String> = listOf("-std=c11", "-g", "-Wall", "-Wextra", "-Werror", "-Iinclude"),
    val wallClockTimeoutMillis: Long = 10L * 60 * 1_000,
    val maximumOutputBytes: Long = 32L * 1024 * 1024,
    val terminationGraceMillis: Long = 5_000,
) {
    init {
        require(makeExecutable.isNotBlank() && '\n' !in makeExecutable && '\r' !in makeExecutable) {
            "make executable must be a non-blank single-line value"
        }
        require(compilerExecutable.matches(Regex("[A-Za-z0-9_./+-]+"))) {
            "compiler executable contains characters that are unsafe in a Make variable"
        }
        require(parallelism in 1..256) { "parallelism must be between 1 and 256" }
        require(cFlags.isNotEmpty() && cFlags.all { it.matches(Regex("[A-Za-z0-9_./=:+,-]+")) }) {
            "C flags contain characters that are unsafe in a Make variable"
        }
        require(cFlags.any { it == "-Werror" }) { "warnings-as-errors (-Werror) is required" }
        require(cFlags.none { it == "-w" || it.startsWith("-Wno-error") }) {
            "C flags cannot disable warnings-as-errors"
        }
        require(wallClockTimeoutMillis > 0) { "build wall-clock limit must be positive" }
        require(maximumOutputBytes in 1 until Int.MAX_VALUE.toLong()) {
            "build output limit must be positive and smaller than 2 GiB"
        }
        require(terminationGraceMillis in 0..30_000) { "build termination grace must be between zero and 30 seconds" }
    }

    fun command(): List<String> = listOf(
        makeExecutable,
        "--jobs=$parallelism",
        "--output-sync=target",
        "CC=$compilerExecutable",
        "CFLAGS=${cFlags.joinToString(" ")}",
    )
}

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

internal fun captureBuildSourceRevision(projectDir: Path): BuildSourceRevision {
    val inputs = Files.walk(projectDir).use { paths ->
        paths.filter { path ->
            if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(path)) return@filter false
            val relative = path.relativeTo(projectDir).pathString.replace('\\', '/')
            relative == "Makefile" || relative.startsWith("src/") || relative.startsWith("include/")
        }.map { path ->
            val relative = path.relativeTo(projectDir).pathString.replace('\\', '/')
            require(relative.isNotBlank() && !relative.startsWith('/') && relative.split('/').none { it in setOf("", ".", "..") }) {
                "build source path is not normalized: $relative"
            }
            val size = Files.size(path)
            BuildSourceInput(relative, size, sha256File(path, size))
        }.toList().sortedBy { it.path }
    }
    require(inputs.isNotEmpty() && inputs.any { it.path == "Makefile" }) {
        "build source revision must contain Makefile and at least one input"
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

private fun sha256File(path: Path, expectedBytes: Long): String {
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

/** Stable owner ID emitted by generated-C builds and consumed by generated-C repair indexing. */
internal fun generatedCUnplannedModuleId(path: String): String =
    if (path == "src/main.c") {
        "entrypoint"
    } else {
        "generated_path_" +
            path.toByteArray(Charsets.UTF_8).joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
    }

object MakeProjectBuilder {
    private data class BuildOwner(
        val id: String,
        val sourcePath: String,
        val objectPath: String,
        val diagnosticFile: String,
    )

    fun build(
        projectDir: Path,
        configuration: ProjectBuildConfiguration = ProjectBuildConfiguration(),
    ): BuildReport {
        require(!Files.isSymbolicLink(projectDir)) { "generated project root must not be a symbolic link" }
        val projectRoot = projectDir.toRealPath()
        require(projectRoot.toString().none { it == '=' || it.code < 0x20 || it.code == 0x7f }) {
            "generated project path cannot be encoded safely in GCC reproducible-prefix mappings: $projectRoot"
        }
        validateBuildProjectTree(projectRoot)
        if (!projectRoot.resolve("Makefile").exists()) {
            throw BuildException("generated project is missing Makefile")
        }
        resetBuildDirectory(projectRoot.resolve("build"))
        val reportsDir = projectRoot.resolve("reports").createDirectories()
        val diagnosticsDir = reportsDir.resolve("build/modules").createDirectories()
        val owners = discoverOwners(projectRoot)
        val command = configuration.command()
        writeBuildInstructions(projectRoot, configuration)
        val sourceRevisionBeforeBuild = captureBuildSourceRevision(projectRoot)
        val processBuilder = ProcessBuilder(command)
            .directory(projectRoot.toFile())
            .redirectErrorStream(true)
        sanitizeBuildEnvironment(processBuilder.environment())
        processBuilder.environment()["PWD"] = projectRoot.toString()
        val process = processBuilder.start()
        val outputFuture = CompletableFuture.supplyAsync {
            val output = java.io.ByteArrayOutputStream()
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            process.inputStream.use { input ->
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    if (output.size().toLong() + count > configuration.maximumOutputBytes) {
                        terminateBuildProcess(process, configuration.terminationGraceMillis)
                        throw BuildException(
                            "build output exceeds ${configuration.maximumOutputBytes} bytes",
                        )
                    }
                    output.write(buffer, 0, count)
                }
            }
            output.toString(Charsets.UTF_8)
        }
        val completed = process.waitFor(configuration.wallClockTimeoutMillis, TimeUnit.MILLISECONDS)
        if (!completed) {
            terminateBuildProcess(process, configuration.terminationGraceMillis)
        }
        val output = try {
            outputFuture.join()
        } catch (failure: CompletionException) {
            throw (failure.cause ?: failure)
        }
        if (!completed) {
            throw BuildException("generated project build exceeded ${configuration.wallClockTimeoutMillis} milliseconds")
        }
        val returnCode = process.exitValue()
        val sourceRevisionAfterBuild = captureBuildSourceRevision(projectRoot)
        val sourceStableDuringBuild = sourceRevisionBeforeBuild == sourceRevisionAfterBuild
        val artifact = projectRoot.resolve("build/reconstructed").takeIf {
            returnCode == 0 && Files.isRegularFile(it, LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(it)
        }?.let { path ->
            val size = Files.size(path)
            BuildArtifactIdentity("build/reconstructed", size, sha256File(path, size))
        }
        val grouped = groupDiagnostics(output, owners)
        val failedOwners = determineFailedOwners(returnCode, grouped)
        Files.list(diagnosticsDir).use { paths ->
            paths.filter { it.isRegularFile() && it.fileName.toString().endsWith(".log") }.forEach(Files::delete)
        }
        writeOwnerDiagnostics(diagnosticsDir, owners, grouped, failedOwners)
        val logPath = reportsDir.resolve("build.log")
        writeProjectEvidenceAtomically(logPath, renderBuildLog(command, returnCode, owners, grouped))
        writeProjectEvidenceAtomically(
            reportsDir.resolve("build_contract.json"),
            renderBuildContract(
                configuration,
                command,
                owners,
                failedOwners,
                returnCode,
                sourceRevisionBeforeBuild,
                sourceStableDuringBuild,
                artifact,
            ),
        )
        if (!sourceStableDuringBuild) {
            throw BuildException("build source inputs changed while the build command was running; see ${logPath.pathString}")
        }
        if (returnCode == 0 && artifact == null) {
            throw BuildException("build command succeeded without producing build/reconstructed; see ${logPath.pathString}")
        }
        if (returnCode != 0) {
            throw BuildException(
                "generated project failed to build; owners=${failedOwners.joinToString(",")}; " +
                    "see ${logPath.pathString} and ${diagnosticsDir.pathString}",
            )
        }
        return BuildReport(
            projectDir = projectRoot,
            returnCode = returnCode,
            logPath = logPath,
            diagnosticsDir = diagnosticsDir,
            failedOwners = failedOwners,
            command = command,
        )
    }

    internal fun terminateBuildProcess(process: Process, graceMillis: Long) {
        val handles = (process.toHandle().descendants().toList().asReversed() + process.toHandle()).distinct()
        handles.forEach { if (it.isAlive) it.destroy() }
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(graceMillis)
        handles.forEach { handle ->
            val remaining = deadline - System.nanoTime()
            if (handle.isAlive && remaining > 0) {
                runCatching { handle.onExit().get(remaining, TimeUnit.NANOSECONDS) }
            }
        }
        handles.forEach { if (it.isAlive) it.destroyForcibly() }
        handles.forEach { handle -> if (handle.isAlive) runCatching { handle.onExit().get(5, TimeUnit.SECONDS) } }
    }

    private fun discoverOwners(projectDir: Path): List<BuildOwner> {
        val planPath = projectDir.resolve("reports/module_plan.json")
        val planned = if (planPath.isRegularFile()) {
            val root = Json.parseToJsonElement(planPath.readText()).jsonObject
            root["modules"]?.jsonArray.orEmpty().associate { element ->
                val module = element.jsonObject
                module.getValue("sourcePath").jsonPrimitive.content.replace('\\', '/') to
                    module.getValue("id").jsonPrimitive.content
            }
        } else {
            emptyMap()
        }
        val sourcesRoot = projectDir.resolve("src")
        require(Files.isDirectory(sourcesRoot)) { "generated project is missing src directory" }
        val sources = Files.walk(sourcesRoot).use { paths ->
            paths.filter { it.isRegularFile() && it.fileName.toString().endsWith(".c") }
                .map { it.relativeTo(projectDir).pathString.replace('\\', '/') }
                .toList()
                .sorted()
        }
        require(sources.isNotEmpty()) { "generated project has no C sources" }
        val ownerIds = sources.associateWith { source ->
            planned[source] ?: generatedCUnplannedModuleId(source)
        }
        require(planned.keys.all { it in sources }) {
            "module plan references missing sources: ${(planned.keys - sources.toSet()).sorted().joinToString(",")}"
        }
        val diagnosticNames = ownerIds.values.associateWith { safeIdentifier(it) }
        val collisions = diagnosticNames.entries.groupBy { it.value }.filterValues { it.size > 1 }
        require(collisions.isEmpty()) { "module IDs collide as diagnostic file names: ${collisions.keys.sorted().joinToString(",")}" }
        return sources.map { source ->
            val id = ownerIds.getValue(source)
            BuildOwner(
                id = id,
                sourcePath = source,
                objectPath = "build/${source.removePrefix("src/").removeSuffix(".c")}.o",
                diagnosticFile = "${diagnosticNames.getValue(id)}.log",
            )
        }
    }

    private fun validateBuildProjectTree(projectDir: Path) {
        Files.walk(projectDir).use { paths ->
            paths.forEach { path ->
                require(!Files.isSymbolicLink(path)) { "generated build project contains a symbolic link: $path" }
                require(
                    Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS) ||
                        Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS),
                ) {
                    "generated build project contains a non-regular filesystem entry: $path"
                }
            }
        }
    }

    private fun resetBuildDirectory(buildDir: Path) {
        if (!Files.exists(buildDir, LinkOption.NOFOLLOW_LINKS)) return
        Files.walk(buildDir).use { paths ->
            paths.sorted(Comparator.reverseOrder()).forEach(Files::delete)
        }
    }

    private fun groupDiagnostics(output: String, owners: List<BuildOwner>): Map<String, List<String>> {
        val grouped = linkedMapOf<String, MutableList<String>>()
        owners.forEach { grouped[it.id] = mutableListOf() }
        grouped["link"] = mutableListOf()
        grouped["project"] = mutableListOf()
        var currentOwner = "project"
        output.lineSequence().forEach { line ->
            val sourceOwner = owners.firstOrNull { line.contains(it.sourcePath) }
            val objectOwner = owners.firstOrNull { line.contains("${it.objectPath}:") }
            currentOwner = when {
                line.startsWith("[link] ") || line.contains("-o build/reconstructed") -> "link"
                sourceOwner != null -> sourceOwner.id
                objectOwner != null -> objectOwner.id
                else -> currentOwner
            }
            grouped.getValue(currentOwner) += line
        }
        return grouped.mapValues { (_, lines) -> lines.toList() }
    }

    private fun determineFailedOwners(returnCode: Int, grouped: Map<String, List<String>>): List<String> {
        if (returnCode == 0) return emptyList()
        val failure = Regex("fatal error:|error:|undefined reference|No rule to make target|\\*\\*\\*", RegexOption.IGNORE_CASE)
        val explicit = grouped.filterValues { lines -> lines.any { failure.containsMatchIn(it) } }.keys
        return (explicit.ifEmpty { setOf("project") }).sorted()
    }

    private fun writeOwnerDiagnostics(
        diagnosticsDir: Path,
        owners: List<BuildOwner>,
        grouped: Map<String, List<String>>,
        failedOwners: List<String>,
    ) {
        owners.sortedBy { it.id }.forEach { owner ->
            val lines = grouped[owner.id].orEmpty()
            val status = when {
                owner.id in failedOwners -> "failed"
                lines.isEmpty() -> "not-run-or-up-to-date"
                else -> "compiled"
            }
            writeProjectEvidenceAtomically(
                diagnosticsDir.resolve(owner.diagnosticFile),
                buildString {
                    append("owner=").append(owner.id).append('\n')
                    append("source=").append(owner.sourcePath).append('\n')
                    append("status=").append(status).append("\n\n")
                    append("[compiler-output]\n")
                    if (lines.isEmpty()) append("<none>\n") else append(lines.joinToString("\n", postfix = "\n"))
                },
            )
        }
        listOf("link", "project").forEach { owner ->
            val lines = grouped[owner].orEmpty()
            if (lines.isNotEmpty() || owner in failedOwners) {
                writeProjectEvidenceAtomically(
                    diagnosticsDir.resolve("_$owner.log"),
                    "owner=$owner\nstatus=${if (owner in failedOwners) "failed" else "completed"}\n\n" +
                        "[build-output]\n${lines.joinToString("\n", postfix = "\n")}",
                )
            }
        }
    }

    private fun renderBuildLog(
        command: List<String>,
        returnCode: Int,
        owners: List<BuildOwner>,
        grouped: Map<String, List<String>>,
    ): String = buildString {
        append("$ ").append(command.joinToString(" ", transform = ::shellDisplay)).append('\n')
        append("exit_code=").append(returnCode).append("\n")
        (owners.map { it.id }.distinct().sorted() + listOf("link", "project")).forEach { owner ->
            val lines = grouped[owner].orEmpty()
            if (lines.isNotEmpty()) {
                append("\n[owner:").append(owner).append("]\n")
                append(lines.joinToString("\n", postfix = "\n"))
            }
        }
    }

    private fun renderBuildContract(
        configuration: ProjectBuildConfiguration,
        command: List<String>,
        owners: List<BuildOwner>,
        failedOwners: List<String>,
        returnCode: Int,
        sourceRevision: BuildSourceRevision,
        sourceStableDuringBuild: Boolean,
        artifact: BuildArtifactIdentity?,
    ): String = buildString {
        append("{\n  \"schemaVersion\": 2,")
        append("\n  \"command\": [")
        append(command.joinToString(",") { "\"${it.escapeJson()}\"" })
        append("],\n  \"parallelism\": ").append(configuration.parallelism).append(',')
        append("\n  \"wallClockTimeoutMillis\": ").append(configuration.wallClockTimeoutMillis).append(',')
        append("\n  \"maximumOutputBytes\": ").append(configuration.maximumOutputBytes).append(',')
        append("\n  \"warningsAsErrors\": true,")
        append("\n  \"reproduciblePathMapping\": true,")
        append("\n  \"declaredDependencies\": [\"GNU Make\",\"C compiler (")
            .append(configuration.compilerExecutable.escapeJson())
            .append(")\",\"POSIX shell\",\"POSIX find\",\"POSIX mkdir\",\"POSIX rm\"],")
        append("\n  \"apiCredentialsRequired\": false,")
        append("\n  \"analysisCachesRequired\": false,")
        append("\n  \"returnCode\": ").append(returnCode).append(',')
        append("\n  \"sourceStableDuringBuild\": ").append(sourceStableDuringBuild).append(',')
        append("\n  \"sourceRevisionSha256\": \"").append(sourceRevision.sha256).append("\",")
        append("\n  \"sourceInputs\": [")
        append(sourceRevision.inputs.joinToString(",") { input ->
            "{\"path\":\"${input.path.escapeJson()}\",\"bytes\":${input.bytes},\"sha256\":\"${input.sha256}\"}"
        })
        append("],\n  \"artifact\": ")
        append(artifact?.let { identity ->
            "{\"path\":\"${identity.path}\",\"bytes\":${identity.bytes},\"sha256\":\"${identity.sha256}\"}"
        } ?: "null").append(',')
        append("\n  \"failedOwners\": [")
        append(failedOwners.joinToString(",") { "\"${it.escapeJson()}\"" })
        append("],\n  \"modules\": [")
        append(owners.sortedBy { it.id }.joinToString(",") { owner ->
            "{\"id\":\"${owner.id.escapeJson()}\",\"source\":\"${owner.sourcePath.escapeJson()}\",\"diagnostics\":\"reports/build/modules/${owner.diagnosticFile.escapeJson()}\"}"
        })
        append("]\n}\n")
    }

    private fun writeBuildInstructions(projectDir: Path, configuration: ProjectBuildConfiguration) {
        val command = configuration.command().joinToString(" ", transform = ::shellDisplay)
        writeProjectEvidenceAtomically(
            projectDir.resolve("BUILDING.md"),
            """
            # Build the reconstructed project

            From this directory, run the following single parallel build command:

            ```sh
            $command
            ```

            The build requires GNU Make, the configured C compiler `${configuration.compilerExecutable}`, a POSIX shell, and the POSIX `find`, `mkdir`, and `rm` utilities. `-Werror` is mandatory. The generated Makefile maps file, macro, and debug paths to a project-relative root so identical accepted source revisions do not retain workstation paths. The build does not require analysis caches, network access, or API credentials. Per-module compiler diagnostics are written under `reports/build/modules/`; `reports/build_contract.json` maps every source to its owning module.
            """.trimIndent() + "\n",
        )
    }

    internal fun sanitizeBuildEnvironment(environment: MutableMap<String, String>) {
        val sensitive = Regex("(^|_)(API(_|$)|TOKEN($|_)|SECRET($|_)|PASSWORD($|_)|BASE_URL$|MODEL$|CACHE($|_))", RegexOption.IGNORE_CASE)
        environment.keys.filter { sensitive.containsMatchIn(it) }.toList().forEach(environment::remove)
        environment.remove("MAKEFLAGS")
        environment.remove("MFLAGS")
        listOf(
            "CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "LIBRARY_PATH", "COMPILER_PATH",
            "GCC_EXEC_PREFIX", "LD_PRELOAD", "CPPFLAGS", "LDFLAGS",
        ).forEach(environment::remove)
        environment["LC_ALL"] = "C"
        environment["LANG"] = "C"
        environment["TZ"] = "UTC"
        environment["SOURCE_DATE_EPOCH"] = "0"
    }

    private fun shellDisplay(argument: String): String =
        if (argument.matches(Regex("[A-Za-z0-9_./:=+-]+"))) argument
        else "'${argument.replace("'", "'\\''")}'"
}

class ReconstructionPipeline(private val analyzer: GhidraJvmAnalyzer) {
    fun generate(binaryPath: Path, workDir: Path): BuildReport {
        val analysis = analyzer.analyze(binaryPath, workDir.resolve("analysis"))
        val projectDir = RecompilableProjectGenerator.generate(analysis, workDir.resolve("project"))
        return MakeProjectBuilder.build(projectDir)
    }
}
