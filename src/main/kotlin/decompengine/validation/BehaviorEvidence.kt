package decompengine.validation

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.project.GeneratedCMakeReconstructionProfile
import decompengine.project.ReconstructionProfile
import decompengine.project.SourceTreeManifestReader
import decompengine.repair.readStableRegularFile
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull

class BehaviorProjectContext(
    val projectDir: Path,
    val profile: ReconstructionProfile = GeneratedCMakeReconstructionProfile.descriptor,
)

internal class BehaviorEvidenceCapture {
    private data class ObservedFile(val identity: Any, val document: JsonObject)

    private val observed = linkedMapOf<Path, ObservedFile>()
    private var totalBytes = 0L

    fun executable(path: Path): JsonObject {
        require(Files.isExecutable(path)) { "behavior executable is unavailable: $path" }
        return file(path).also { require(it.count("bytes") > 0L) { "behavior executable is empty: $path" } }
    }

    fun file(path: Path): JsonObject {
        val absolute = path.toAbsolutePath().normalize()
        val snapshot = readStableRegularFile(absolute.parent, absolute.fileName.toString(), MAXIMUM_FILE_BYTES)
        val document = JsonObject(mapOf(
            "bytes" to JsonPrimitive(snapshot.bytes.size),
            "sha256" to JsonPrimitive(snapshot.sha256),
        ))
        val current = ObservedFile(snapshot.identity, document)
        val previous = observed.putIfAbsent(absolute, current)
        require(previous == null || previous == current) { "behavior input changed while captured: $absolute" }
        if (previous == null) {
            totalBytes = Math.addExact(totalBytes, snapshot.bytes.size.toLong())
            require(totalBytes <= MAXIMUM_TOTAL_BYTES && observed.size <= MAXIMUM_FILES) {
                "behavior evidence inputs exceed their aggregate bound"
            }
        }
        return document
    }

    fun document(path: Path): JsonObject {
        val expected = file(path)
        val absolute = path.toAbsolutePath().normalize()
        val snapshot = readStableRegularFile(absolute.parent, absolute.fileName.toString(), MAXIMUM_FILE_BYTES)
        require(snapshot.sha256 == expected.string("sha256")) { "behavior JSON changed during capture" }
        return OracleJson.parse(snapshot.bytes, BEHAVIOR_JSON_LIMITS).jsonObject
    }

    fun project(context: BehaviorProjectContext, original: JsonObject, rebuilt: Path): JsonObject {
        val root = context.projectDir.toAbsolutePath().normalize()
        val manifestPath = root.resolve("source_tree_manifest.json")
        val manifestIdentity = file(manifestPath)
        val manifestDocument = document(manifestPath)
        val manifest = SourceTreeManifestReader.parse(manifestDocument.toString(), context.profile)
        require(manifest.inputSha256 == original.string("sha256")) { "behavior original differs from the project input" }
        require(manifest.files.size <= MAXIMUM_FILES) { "behavior project exceeds its file-count bound" }
        val files = manifest.files.sortedBy { it.path }.map { entry ->
            val identity = file(root.resolve(entry.path))
            require(identity.string("sha256") == entry.sha256) { "behavior project manifest differs from ${entry.path}" }
            JsonObject(identity + ("path" to JsonPrimitive(entry.path)))
        }
        val contractPath = root.resolve("reports/build_contract.json")
        val contractIdentity = file(contractPath)
        val contract = document(contractPath)
        require(contract.keys == setOf("schemaVersion", "command", "parallelism", "wallClockTimeoutMillis",
            "maximumOutputBytes", "warningsAsErrors", "reproduciblePathMapping", "declaredDependencies",
            "apiCredentialsRequired", "analysisCachesRequired", "returnCode", "sourceStableDuringBuild",
            "sourceRevisionSha256", "sourceInputs", "artifact", "failedOwners", "modules")) {
            "behavior build contract has missing or unknown fields"
        }
        require(contract.integer("schemaVersion") == 2 && contract.integer("returnCode") == 0 &&
            contract.boolean("sourceStableDuringBuild") && contract.boolean("warningsAsErrors") &&
            contract.boolean("reproduciblePathMapping") && !contract.boolean("apiCredentialsRequired") &&
            !contract.boolean("analysisCachesRequired") && contract.getValue("failedOwners").jsonArray.isEmpty()
        ) { "behavior requires a successful source-stable build contract" }
        require(contract.integer("parallelism") in 1..256 && contract.count("wallClockTimeoutMillis") > 0 &&
            contract.count("maximumOutputBytes") > 0)
        listOf("command", "declaredDependencies").forEach { name ->
            require(contract.getValue(name).jsonArray.isNotEmpty())
            contract.getValue(name).jsonArray.forEach { require(it.jsonPrimitive.isString) }
        }
        contract.getValue("modules").jsonArray.forEach { element ->
            val module = element.jsonObject
            require(module.keys == setOf("id", "source", "diagnostics"))
            module.keys.forEach { module.string(it) }
        }
        val inputs = sourceInputs(root)
        val sourceRevision = behaviorSourceRevisionSha256(inputs)
        require(contract.string("sourceRevisionSha256") == sourceRevision &&
            contract.getValue("sourceInputs") == inputs
        ) { "behavior build contract does not match the current source revision" }
        val artifact = contract.getValue("artifact").jsonObject
        require(artifact.keys == setOf("path", "bytes", "sha256")) { "behavior build artifact fields are invalid" }
        val relative = artifact.string("path")
        require(relative == "build/reconstructed" && root.resolve(relative) == rebuilt.toAbsolutePath().normalize()) {
            "behavior rebuilt executable is not the build-contract artifact"
        }
        require(JsonObject(artifact - "path") == executable(rebuilt)) { "behavior rebuilt executable differs from the build contract" }
        return JsonObject(mapOf(
            "profileId" to JsonPrimitive(manifest.profileId),
            "profileSha256" to JsonPrimitive(manifest.profileSha256),
            "inputSha256" to JsonPrimitive(manifest.inputSha256),
            "manifest" to manifestIdentity,
            "files" to JsonArray(files),
            "buildContract" to contractIdentity,
            "sourceRevisionSha256" to JsonPrimitive(sourceRevision),
            "sourceInputs" to inputs,
            "artifact" to artifact,
        ))
    }

    private fun sourceInputs(root: Path): JsonArray {
        val paths = mutableListOf(root.resolve("Makefile"))
        var entries = 1
        for (name in listOf("src", "include")) {
            val directory = root.resolve(name)
            if (!Files.exists(directory, LinkOption.NOFOLLOW_LINKS)) continue
            require(Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) { "behavior source root is not a directory: $name" }
            Files.walk(directory, 32).use { stream ->
                val iterator = stream.iterator()
                while (iterator.hasNext()) {
                    require(++entries <= MAXIMUM_FILES) { "behavior source inventory exceeds its entry bound" }
                    val path = iterator.next()
                    if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
                        if (directory.relativize(path).nameCount >= 32) {
                            require(Files.newDirectoryStream(path).use { !it.iterator().hasNext() }) {
                                "behavior source inventory exceeds its depth bound"
                            }
                        }
                    } else {
                        require(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
                            "behavior source inventory contains an indirect or special file: $path"
                        }
                        paths.add(path)
                    }
                }
            }
        }
        return JsonArray(paths.sortedBy { root.relativize(it).toString() }.map { path ->
            JsonObject(file(path) + ("path" to JsonPrimitive(root.relativize(path).toString())))
        })
    }

    fun requireCurrent() {
        for ((path, expected) in observed) {
            val snapshot = readStableRegularFile(path.parent, path.fileName.toString(), MAXIMUM_FILE_BYTES)
            require(snapshot.identity == expected.identity && snapshot.sha256 == expected.document.string("sha256") &&
                snapshot.bytes.size.toLong() == expected.document.count("bytes")
            ) { "behavior evidence input changed during execution: $path" }
        }
    }

    companion object {
        const val MAXIMUM_FILE_BYTES = 64L * 1024 * 1024
        const val MAXIMUM_TOTAL_BYTES = 512L * 1024 * 1024
        const val MAXIMUM_FILES = 10_000
    }
}

internal object BehaviorEvidence {
    const val MAXIMUM_REPORT_BYTES = 64L * 1024 * 1024
    private const val PROVIDER = "local-revision-bound-behavior-v1"

    fun inputCorpusSha256(inputs: List<ProcessInput>, fileInputs: Map<String, JsonArray>): String {
        val cases = JsonArray(inputs.map { input -> JsonObject(mapOf(
            "id" to JsonPrimitive(input.id),
            "args" to JsonArray(input.args.map(::JsonPrimitive)),
            "stdinHex" to JsonPrimitive(java.util.HexFormat.of().formatHex(input.stdin)),
            "fileInputs" to (fileInputs[input.id] ?: JsonArray(emptyList())),
        )) })
        return hash(corpus(cases, includeFileLocators = false))
    }

    fun encode(
        legacy: JsonObject,
        original: JsonObject,
        rebuilt: JsonObject,
        policy: JsonObject,
        project: JsonObject?,
        fileInputs: Map<String, JsonArray> = emptyMap(),
    ): String {
        val cases = JsonArray(legacy.getValue("cases").jsonArray.map { element ->
            val case = element.jsonObject
            JsonObject(case + ("fileInputs" to (fileInputs[case.string("id")] ?: JsonArray(emptyList()))))
        })
        val body = JsonObject(legacy + mapOf(
            "cases" to cases,
            "schemaVersion" to JsonPrimitive(4),
            "provider" to JsonPrimitive("local-revision-bound-behavior-v4"),
            "originalIdentity" to original,
            "rebuiltIdentity" to rebuilt,
            "executionPolicy" to policy,
            "projectRevision" to (project ?: JsonNull),
            "corpusSha256" to JsonPrimitive(hash(corpus(cases, includeFileLocators = false))),
            "observationsSha256" to JsonPrimitive(hash(cases)),
        ))
        val record = JsonObject(body + ("reportSha256" to JsonPrimitive(hash(body))))
        validate(record)
        return kotlinx.serialization.json.Json { prettyPrint = true }.encodeToString(JsonObject.serializer(), record) + "\n"
    }

    fun decode(bytes: ByteArray): JsonObject {
        require(bytes.size <= MAXIMUM_REPORT_BYTES) { "behavior report exceeds its byte bound" }
        return OracleJson.parse(bytes, BEHAVIOR_JSON_LIMITS).jsonObject.also(::validate)
    }

    fun requireProjectCurrent(record: JsonObject, context: BehaviorProjectContext) {
        val project = record.getValue("projectRevision") as? JsonObject
            ?: error("behavior report is not bound to a project revision")
        val capture = BehaviorEvidenceCapture()
        val rebuilt = context.projectDir.resolve(project.getValue("artifact").jsonObject.string("path"))
        require(capture.project(context, record.getValue("originalIdentity").jsonObject, rebuilt) == project) {
            "behavior evidence refers to a stale or foreign project revision"
        }
        require(capture.file(rebuilt) == record.getValue("rebuiltIdentity")) { "behavior rebuilt identity changed" }
        capture.requireCurrent()
    }

    private fun validate(root: JsonObject) {
        require(root.keys == setOf(
            "schemaVersion", "provider", "id", "sandbox", "networkIsolated", "originalBinary", "rebuiltBinary",
            "matches", "cases", "originalIdentity", "rebuiltIdentity", "executionPolicy", "projectRevision",
            "corpusSha256", "observationsSha256", "reportSha256",
        )) { "behavior report has missing or unknown fields" }
        val schemaVersion = root.integer("schemaVersion")
        require((schemaVersion == 1 && root.string("provider") == PROVIDER) ||
            (schemaVersion == 2 && root.string("provider") == "local-revision-bound-behavior-v2") ||
            (schemaVersion == 3 && root.string("provider") == "local-revision-bound-behavior-v3") ||
            (schemaVersion == 4 && root.string("provider") == "local-revision-bound-behavior-v4")) { "unsupported behavior report" }
        require(root.string("id").matches(Regex("[A-Za-z0-9][A-Za-z0-9_.-]{0,127}"))) { "invalid behavior report ID" }
        require(root.string("sandbox") == "bubblewrap") { "unsupported behavior sandbox request" }
        val originalPath = absolutePath(root.string("originalBinary"))
        val rebuiltPath = absolutePath(root.string("rebuiltBinary"))
        identity(root.getValue("originalIdentity").jsonObject)
        identity(root.getValue("rebuiltIdentity").jsonObject)
        require(root.getValue("originalIdentity").jsonObject.count("bytes") > 0L &&
            root.getValue("rebuiltIdentity").jsonObject.count("bytes") > 0L)
        val policy = root.getValue("executionPolicy").jsonObject
        require(policy.keys == setOf("assurance", "environment", "workingDirectory", "networkIsolationRequested",
            "timeoutMillis", "maximumStdoutBytes", "maximumStderrBytes", "maximumAggregateBytes",
            "maximumComparisonOutputBytes", "bubblewrap", "timeout") +
            if (schemaVersion == 4) setOf("completionLauncher", "maximumCompletionBytes") else emptySet<String>()) {
            "behavior execution policy is not closed"
        }
        require(policy.string("assurance") == "local-path-stability-checks-not-production-authority" &&
            policy.getValue("environment") == JsonObject(mapOf("PATH" to JsonPrimitive("/usr/bin"))) &&
            policy.string("workingDirectory") == "/tmp"
        ) { "behavior execution policy is unsupported" }
        listOf("timeoutMillis", "maximumStdoutBytes", "maximumStderrBytes", "maximumAggregateBytes", "maximumComparisonOutputBytes").forEach {
            require(policy.count(it) > 0L) { "behavior policy bound is empty" }
        }
        require(policy.count("maximumComparisonOutputBytes") <= 16L * 1024 * 1024)
        fun executable(name: String): Path {
            val executable = policy.getValue(name).jsonObject
            require(executable.keys == setOf("path", "bytes", "sha256"))
            identity(JsonObject(executable - "path"))
            require(executable.count("bytes") > 0L)
            return absolutePath(executable.string("path"))
        }
        val bubblewrap = executable("bubblewrap")
        val timeout = executable("timeout")
        val launcher = if (schemaVersion == 4) executable("completionLauncher") else null
        if (schemaVersion == 4) require(policy.count("maximumCompletionBytes") == MAXIMUM_BUBBLEWRAP_COMPLETION_BYTES.toLong())
        val network = policy.boolean("networkIsolationRequested")
        require(root.boolean("networkIsolated") == network) { "behavior network request is contradictory" }
        val cases = root.getValue("cases").jsonArray
        require(cases.size in 1..1024) { "behavior case count is outside its bound" }
        val identifiers = hashSetOf<String>()
        var observedOutputBytes = 0L
        var stdinBytes = 0L
        var argumentBytes = 0L
        var fileBytes = 0L
        var fileCount = 0L
        val matches = cases.map { element ->
            val case = element.jsonObject
            require(case.keys == setOf("id", "args", "stdinHex", "matches", "exitCodeMatches", "stdoutMatches",
                "stderrMatches", "original", "rebuilt") + if (schemaVersion >= 2) setOf("fileInputs") else emptySet<String>()) { "behavior case fields are not closed" }
            val inputFiles = if (schemaVersion >= 2) case.getValue("fileInputs").jsonArray.map { element ->
                val file = element.jsonObject
                require(file.keys == setOf("name", "sourcePath", "bytes", "sha256", "contentHex")) { "behavior input file fields are not closed" }
                val name = file.string("name")
                val source = absolutePath(file.string("sourcePath"))
                identity(JsonObject(file.filterKeys { it in setOf("bytes", "sha256") }))
                val hex = file.string("contentHex")
                requireHex(hex)
                require(file.count("bytes") == hex.length / 2L) { "behavior input file length differs from retained bytes" }
                fileBytes = Math.addExact(fileBytes, file.count("bytes"))
                fileCount++
                require(fileBytes <= MAXIMUM_BEHAVIOR_FILE_BYTES && fileCount <= MAXIMUM_BEHAVIOR_INPUT_FILES) { "behavior file corpus exceeds its bound" }
                require(OracleArtifacts.sha256(java.util.HexFormat.of().parseHex(hex)) == file.string("sha256")) { "behavior input file digest differs from retained bytes" }
                name to source
            } else emptyList()
            require(inputFiles.map { it.first } == inputFiles.map { it.first }.distinct().sorted()) { "behavior input files must be unique and sorted" }
            requireBehaviorFileNames(inputFiles.map { it.first })
            val identifier = case.string("id")
            require(identifier.isNotEmpty() && identifier.length <= 256 && identifiers.add(identifier)) { "behavior case IDs are invalid or duplicated" }
            val arguments = case.getValue("args").jsonArray.map { argument ->
                require(argument.jsonPrimitive.isString)
                argument.jsonPrimitive.content.also { require(it.length <= 64 * 1024 && '\u0000' !in it) }
            }
            require(arguments.size <= 256)
            requireHex(case.string("stdinHex"))
            stdinBytes += case.string("stdinHex").length / 2
            argumentBytes += arguments.sumOf { it.toByteArray().size.toLong() }
            require(stdinBytes <= 8L * 1024 * 1024 && argumentBytes <= 1024L * 1024)
            val original = output(case.getValue("original").jsonObject, network, schemaVersion)
            val rebuilt = output(case.getValue("rebuilt").jsonObject, network, schemaVersion)
            for ((observation, path) in listOf(original to originalPath, rebuilt to rebuiltPath)) {
                val stdoutBytes = observation.string("stdoutHex").length.toLong() / 2
                val stderrBytes = observation.string("stderrHex").length.toLong() / 2
                require(stdoutBytes <= policy.count("maximumStdoutBytes") && stderrBytes <= policy.count("maximumStderrBytes") &&
                    stdoutBytes + stderrBytes <= policy.count("maximumAggregateBytes")) { "behavior output exceeds its recorded policy" }
                observedOutputBytes += stdoutBytes + stderrBytes
                require(observedOutputBytes <= policy.count("maximumComparisonOutputBytes"))
                val expectedCommand = behaviorSandboxCommand(path, arguments, policy.count("timeoutMillis"), bubblewrap, timeout, network, inputFiles.toMap())
                // Historical records used integer-second native timeouts; the JVM watchdog
                // still enforced the recorded millisecond limit. Preserve their exact recipe.
                val historicalCommand = expectedCommand.toMutableList().apply {
                    this[1] = "${maxOf(1L, policy.count("timeoutMillis") / 1000L)}s"
                }
                val recordedCommand = observation.getValue("sandboxCommand")
                require(recordedCommand == JsonArray(expectedCommand.map(::JsonPrimitive)) ||
                    (schemaVersion < 4 && recordedCommand == JsonArray(historicalCommand.map(::JsonPrimitive)))) {
                    "behavior sandbox command contradicts its inputs or execution policy"
                }
                if (schemaVersion == 4) {
                    val completion = observation.getValue("completionEvidence").jsonObject
                    require(completion.keys == setOf("channelPath", "statusHex", "launchCommand"))
                    require(completion.string("channelPath").length <= 4096)
                    val channel = absolutePath(completion.string("channelPath"))
                    val hex = completion.string("statusHex")
                    require(hex.length <= MAXIMUM_BUBBLEWRAP_COMPLETION_BYTES * 2)
                    requireHex(hex)
                    parseBubblewrapCompletion(java.util.HexFormat.of().parseHex(hex), observation.integer("exitCode"))
                    require(completion.getValue("launchCommand") == JsonArray(
                        completionLaunchCommand(expectedCommand, requireNotNull(launcher), channel).map(::JsonPrimitive))) {
                        "completion launcher command contradicts the sandbox request"
                    }
                }
            }
            val exit = original.integer("exitCode") == rebuilt.integer("exitCode")
            val stdout = original.string("stdoutHex") == rebuilt.string("stdoutHex")
            val stderr = original.string("stderrHex") == rebuilt.string("stderrHex")
            require(case.boolean("exitCodeMatches") == exit && case.boolean("stdoutMatches") == stdout &&
                case.boolean("stderrMatches") == stderr && case.boolean("matches") == (exit && stdout && stderr)) {
                "behavior comparison flags contradict recorded observations"
            }
            exit && stdout && stderr
        }
        require(root.boolean("matches") == matches.all { it }) { "behavior summary contradicts its cases" }
        val project = root.getValue("projectRevision")
        if (project != JsonNull) {
            val revision = project.jsonObject
            require(revision.keys == setOf("profileId", "profileSha256", "inputSha256", "manifest", "files",
                "buildContract", "sourceRevisionSha256", "sourceInputs", "artifact")) { "behavior revision is not closed" }
            revision.string("profileId")
            listOf("profileSha256", "inputSha256", "sourceRevisionSha256").forEach { requireHash(revision.string(it)) }
            identity(revision.getValue("manifest").jsonObject)
            identity(revision.getValue("buildContract").jsonObject)
            listOf("files", "sourceInputs").forEach { name ->
                val files = revision.getValue(name).jsonArray
                require(files.size in 1..BehaviorEvidenceCapture.MAXIMUM_FILES)
                val paths = files.map { file ->
                    val item = file.jsonObject
                    require(item.keys == setOf("path", "bytes", "sha256"))
                    identity(JsonObject(item - "path"))
                    item.string("path").also(::relativePath)
                }
                require(paths == paths.sorted() && paths.distinct().size == paths.size)
            }
            require(revision.string("sourceRevisionSha256") == behaviorSourceRevisionSha256(revision.getValue("sourceInputs").jsonArray)) {
                "behavior source revision does not match its input commitments"
            }
            val artifact = revision.getValue("artifact").jsonObject
            require(artifact.keys == setOf("path", "bytes", "sha256"))
            relativePath(artifact.string("path"))
            require(JsonObject(artifact - "path") == root.getValue("rebuiltIdentity"))
            require(revision.string("inputSha256") == root.getValue("originalIdentity").jsonObject.string("sha256"))
        }
        require(root.string("corpusSha256") == hash(corpus(cases, includeFileLocators = schemaVersion < 3)) && root.string("observationsSha256") == hash(cases) &&
            root.string("reportSha256") == hash(JsonObject(root - "reportSha256"))) { "behavior commitments do not match their records" }
    }

    private fun output(output: JsonObject, network: Boolean, schemaVersion: Int): JsonObject {
        require(output.keys == setOf("exitCode", "stdoutHex", "stderrHex", "networkIsolated", "sandboxCommand") +
            if (schemaVersion == 4) setOf("completionEvidence") else emptySet<String>())
        if (schemaVersion < 4) rejectReservedWrapperExit(output.integer("exitCode"))
        requireHex(output.string("stdoutHex"))
        requireHex(output.string("stderrHex"))
        require(output.boolean("networkIsolated") == network)
        require(output.getValue("sandboxCommand").jsonArray.isNotEmpty())
        output.getValue("sandboxCommand").jsonArray.forEach { require(it.jsonPrimitive.isString) }
        return output
    }

    private fun corpus(cases: JsonArray, includeFileLocators: Boolean) = JsonArray(cases.map { element ->
        val inputs = element.jsonObject.filterKeys { it in setOf("id", "args", "stdinHex", "fileInputs") }
        if (includeFileLocators || "fileInputs" !in inputs) JsonObject(inputs)
        else JsonObject(inputs + ("fileInputs" to JsonArray(inputs.getValue("fileInputs").jsonArray.map { file ->
            JsonObject(file.jsonObject - "sourcePath")
        })))
    })

    private fun hash(value: JsonElement): String = OracleArtifacts.sha256(OracleJson.canonicalBytes(value, BEHAVIOR_JSON_LIMITS))
    private fun requireHash(value: String) = require(value.matches(Regex("[0-9a-f]{64}")))
    private fun requireHex(value: String) = require(value.length % 2 == 0 && value.all { it in '0'..'9' || it in 'a'..'f' })
    private fun identity(identity: JsonObject) {
        require(identity.keys == setOf("bytes", "sha256") && identity.count("bytes") >= 0)
        requireHash(identity.string("sha256"))
    }
    private fun relativePath(value: String) {
        require(value.isNotEmpty() && !value.startsWith('/') && '\\' !in value &&
            value.split('/').none { it in setOf("", ".", "..") }) { "behavior revision path is not relative and normalized" }
    }
    private fun absolutePath(value: String): Path = Path.of(value).also {
        require(it.isAbsolute && it.normalize() == it) { "behavior executable locator is not absolute and normalized" }
    }
}

private fun behaviorSourceRevisionSha256(inputs: JsonArray): String {
    val canonical = inputs.joinToString("") { element ->
        val input = element.jsonObject
        val path = input.string("path")
        "${path.length}:$path:${input.count("bytes")}:${input.string("sha256")}\n"
    }
    return OracleArtifacts.sha256(canonical.toByteArray(Charsets.UTF_8))
}

internal fun behaviorSandboxCommand(
    executable: Path,
    arguments: List<String>,
    timeoutMillis: Long,
    bubblewrap: Path,
    timeout: Path,
    networkRequested: Boolean,
    files: Map<String, Path> = emptyMap(),
): List<String> = buildList {
    require(timeoutMillis > 0) { "behavior timeout must be positive" }
    requireBehaviorFileNames(files.keys)
    val seconds = timeoutMillis / 1000L
    val remainder = timeoutMillis % 1000L
    val duration = if (remainder == 0L) "${seconds}s" else "$seconds.${remainder.toString().padStart(3, '0')}s"
    addAll(listOf(timeout.toAbsolutePath().normalize().toString(), duration,
        bubblewrap.toAbsolutePath().normalize().toString()))
    if (networkRequested) add("--unshare-net")
    addAll(listOf("--unshare-pid", "--new-session", "--die-with-parent",
        "--ro-bind", "/usr", "/usr", "--ro-bind", "/lib", "/lib", "--ro-bind", "/lib64", "/lib64",
        "--dir", "/tmp", "--dir", "/program", "--ro-bind", executable.toAbsolutePath().normalize().toString(),
        "/program/executable"))
    if (files.isNotEmpty()) {
        addAll(listOf("--dir", "/inputs"))
        val parents = files.keys.flatMap { name ->
            val parts = name.split('/')
            (1 until parts.size).map { parts.take(it).joinToString("/") }
        }.distinct().sortedWith(compareBy<String> { it.count { char -> char == '/' } }.thenBy { it })
        parents.forEach { addAll(listOf("--dir", "/inputs/$it")) }
        files.toSortedMap().forEach { (name, path) ->
            addAll(listOf("--ro-bind", path.toAbsolutePath().normalize().toString(), "/inputs/$name"))
        }
    }
    addAll(listOf("--chdir", "/tmp", "/program/executable"))
    addAll(arguments)
}

private val BEHAVIOR_JSON_LIMITS = StrictJsonLimits(
    maximumInputBytes = 64 * 1024 * 1024,
    maximumCanonicalBytes = 64 * 1024 * 1024,
    maximumDepth = 32,
    maximumNodes = 1_000_000,
    maximumStringBytes = 16 * 1024 * 1024,
    maximumTotalStringBytes = 64 * 1024 * 1024,
    maximumNumberCharacters = 32,
)

internal fun JsonObject.string(name: String): String = getValue(name).jsonPrimitive.let {
    require(it.isString) { "$name must be a string" }
    it.content
}

internal fun JsonObject.boolean(name: String): Boolean = getValue(name).jsonPrimitive.let {
    require(!it.isString) { "$name must be a boolean" }
    requireNotNull(it.booleanOrNull) { "$name must be a boolean" }
}

internal fun JsonObject.integer(name: String): Int = getValue(name).jsonPrimitive.let {
    require(!it.isString) { "$name must be an integer" }
    requireNotNull(it.intOrNull) { "$name must be an integer" }
}

internal fun JsonObject.count(name: String): Long = getValue(name).jsonPrimitive.let {
    require(!it.isString) { "$name must be an integer" }
    requireNotNull(it.longOrNull) { "$name must be an integer" }
}
