package decompengine.oracle.reference

import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.oracle.core.DescriptorBoundAtomicStateFile
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.PosixFilePermissions
import java.util.Base64
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** Immutable child-computation request. Its bytes alone grant no execution or oracle authority. */
internal class ReferenceCorpusWorkerRequest(
    val profilePath: Path,
    val profileBytes: Int,
    val profileSha256: String,
    val batchId: String,
    val controlRoot: Path,
    val operationRequestSha256: String,
) {
    val outputDirectory: Path get() = controlRoot.resolve("reports")
    val workingRoot: Path get() = controlRoot.resolve("state/reference-corpus")
    val temporaryRoot: Path get() = controlRoot.resolve("tmp/reference-corpus")

    init {
        requireAbsoluteReferencePath(profilePath)
        requireAbsoluteReferencePath(controlRoot)
        require(!profilePath.startsWith(controlRoot) && !controlRoot.startsWith(profilePath)) {
            "reference profile must be outside the writable control root"
        }
        require(profileBytes in 1..MAXIMUM_PROFILE_BYTES)
        require(profileSha256.matches(REFERENCE_SHA256) && operationRequestSha256.matches(REFERENCE_SHA256))
        require(batchId.matches(Regex("[A-Za-z0-9][A-Za-z0-9_.-]{0,127}"))) { "invalid reference batch" }
    }

    val canonicalBytes: ByteArray get() = OracleJson.canonicalBytes(JsonObject(mapOf(
        "provider" to JsonPrimitive("reference-corpus-worker-request-v1"),
        "schemaVersion" to JsonPrimitive(1),
        "profilePath" to JsonPrimitive(profilePath.toString()),
        "profileBytes" to JsonPrimitive(profileBytes),
        "profileSha256" to JsonPrimitive(profileSha256),
        "batchId" to JsonPrimitive(batchId),
        "controlRoot" to JsonPrimitive(controlRoot.toString()),
        "operationRequestSha256" to JsonPrimitive(operationRequestSha256),
    )), REFERENCE_REQUEST_LIMITS)

    companion object {
        fun parse(bytes: ByteArray): ReferenceCorpusWorkerRequest {
            val root = OracleJson.parseCanonical(bytes, REFERENCE_REQUEST_LIMITS).jsonObject
            require(root.keys == setOf("provider", "schemaVersion", "profilePath", "profileBytes", "profileSha256",
                "batchId", "controlRoot", "operationRequestSha256")) { "reference request fields differ" }
            fun string(key: String) = root.getValue(key).jsonPrimitive.let { require(it.isString); it.content }
            fun number(key: String) = root.getValue(key).jsonPrimitive.let {
                require(!it.isString && it.content.matches(Regex("0|[1-9][0-9]*")))
                it.content.toInt()
            }
            require(string("provider") == "reference-corpus-worker-request-v1" && number("schemaVersion") == 1)
            return ReferenceCorpusWorkerRequest(Path.of(string("profilePath")), number("profileBytes"),
                string("profileSha256"), string("batchId"), Path.of(string("controlRoot")),
                string("operationRequestSha256")).also {
                require(it.canonicalBytes.contentEquals(bytes)) { "reference request is not its canonical representation" }
            }
        }
    }
}

internal class ReferenceCorpusWorkerException(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

/**
 * Computation inside an already admitted, isolated JVM. The outer retained coordinator alone
 * supplies START, resource authority, authenticated outcome and whole-cgroup absence. This worker
 * has no Docker/Python, nested sandbox, expected-result input, or production launch API.
 */
internal object ReferenceCorpusWorker {
    const val OBSERVATIONS_FILE = "reference-worker-observations.json"
    const val MAXIMUM_OBSERVATION_BYTES = 16 * 1024 * 1024

    @JvmStatic
    fun main(arguments: Array<String>) {
        require(arguments.size == 2 && arguments[1].matches(REFERENCE_SHA256)) {
            "reference worker requires its exact request path and SHA-256"
        }
        val requestPath = Path.of(arguments[0])
        val requestBytes = readStableReferenceFile(requestPath, REFERENCE_REQUEST_LIMITS.maximumInputBytes)
        require(OracleArtifacts.sha256(requestBytes) == arguments[1]) { "reference request differs from launch binding" }
        val request = ReferenceCorpusWorkerRequest.parse(requestBytes)
        require(!requestPath.startsWith(request.controlRoot)) { "reference request is inside the writable control root" }
        require(Path.of("").toAbsolutePath().normalize() == request.controlRoot) {
            "reference worker control root differs from its contained working directory"
        }
        val profileBytes = readStableReferenceFile(request.profilePath, request.profileBytes)
        require(profileBytes.size == request.profileBytes && OracleArtifacts.sha256(profileBytes) == request.profileSha256) {
            "reference profile differs from its admitted request"
        }
        val definition = ReferenceCorpusDefinition.parse(profileBytes)
        val observations = capture(request, definition)
        // No output is published until every invocation, repetition and substitution check passes.
        LinuxFilesystemSyscalls.openRoot(request.outputDirectory).use { reports ->
            DescriptorBoundAtomicStateFile.publishManifestNoReplace(reports, OBSERVATIONS_FILE,
                observations, MAXIMUM_OBSERVATION_BYTES)
        }
    }

    /** Child computation, also exercised by non-authoritative local tests; never a launch authority. */
    internal fun capture(request: ReferenceCorpusWorkerRequest, definition: ReferenceCorpusDefinition): ByteArray {
        require(definition.canonicalBytes.size == request.profileBytes &&
            OracleArtifacts.sha256(definition.canonicalBytes) == request.profileSha256) {
            "reference definition differs from request bytes"
        }
        requirePrivateReferenceDirectory(request.controlRoot)
        listOf("state", "tmp", "reports").forEach { requirePrivateReferenceDirectory(request.controlRoot.resolve(it)) }
        createPrivateReferenceDirectory(request.workingRoot)
        createPrivateReferenceDirectory(request.temporaryRoot)
        val cases = definition.cases.filter { it.batchId == request.batchId }
        require(cases.isNotEmpty() && cases.size <= MAXIMUM_REFERENCE_CASES) { "reference batch has no bounded case population" }
        requireReferenceBatchArtifacts(definition, request.batchId)
        val limits = definition.limits
        require(limits.maximumAggregateOutputBytes in 1L..MAXIMUM_CAPTURE_BYTES.toLong()) {
            "reference aggregate output budget exceeds worker ceiling"
        }
        val aggregate = AtomicLong(0)
        val renderedCases = cases.map { case ->
            val first = invoke(request, definition, case, "first", false, aggregate)
            val second = invoke(request, definition, case, "repeat", false, aggregate)
            if (first.comparable != second.comparable) referenceWorkerFail("${case.id}: independent repetition differs")
            val alternate = invoke(request, definition, case, "alternate", true, aggregate)
            val values = definition.alternateSubstitutionValues(alternate.invokedAs)
            val expectedAlternate = JsonObject(first.comparable + mapOf(
                "stdout" to referenceBlob(definition.substitute(first.stdout, values)),
                "stderr" to referenceBlob(definition.substitute(first.stderr, values)),
            ))
            if (expectedAlternate != alternate.comparable) {
                referenceWorkerFail("${case.id}: declared executable identity substitutions do not explain alternate invocation")
            }
            JsonObject(mapOf(
                "id" to JsonPrimitive(case.id), "batchId" to JsonPrimitive(case.batchId),
                "arguments" to JsonArray(case.arguments.map(::JsonPrimitive)),
                "environment" to referenceEnvironment(case.environment),
                "inputs" to JsonArray(case.inputs.map { input -> JsonObject(mapOf(
                    "path" to JsonPrimitive(input.path), "bytes" to JsonPrimitive(input.bytes), "sha256" to JsonPrimitive(input.sha256),
                )) }),
                "stdin" to referenceBlob(case.stdin), "repetitions" to JsonPrimitive(2),
                "observed" to first.comparable,
                "invocations" to JsonArray(listOf(first.record, second.record, alternate.record)),
            ))
        }
        requireReferenceBatchArtifacts(definition, request.batchId)
        val output = JsonObject(mapOf(
            "provider" to JsonPrimitive("reference-corpus-worker-observations-v1"),
            "schemaVersion" to JsonPrimitive(1), "profileId" to JsonPrimitive(definition.id),
            "profileSha256" to JsonPrimitive(request.profileSha256),
            "requestSha256" to JsonPrimitive(OracleArtifacts.sha256(request.canonicalBytes)),
            "operationRequestSha256" to JsonPrimitive(request.operationRequestSha256),
            "batchId" to JsonPrimitive(request.batchId), "caseIds" to JsonArray(cases.map { JsonPrimitive(it.id) }),
            "capturedOutputBytes" to JsonPrimitive(aggregate.get()),
            "cases" to JsonArray(renderedCases),
            "executionAuthenticated" to JsonPrimitive(false), "referenceAuthority" to JsonPrimitive(false),
            "containmentAuthority" to JsonPrimitive(false), "releaseEligible" to JsonPrimitive(false),
        ))
        return OracleJson.canonicalBytes(output, REFERENCE_REPORT_LIMITS)
    }

    private fun invoke(
        request: ReferenceCorpusWorkerRequest,
        definition: ReferenceCorpusDefinition,
        case: ReferenceCorpusCase,
        attempt: String,
        alternate: Boolean,
        aggregate: AtomicLong,
    ): CapturedReferenceInvocation {
        val work = request.workingRoot.resolve("${case.id}-$attempt")
        val temporary = request.temporaryRoot.resolve("${case.id}-$attempt")
        createPrivateReferenceDirectory(work)
        createPrivateReferenceDirectory(temporary)
        for (input in case.inputs) {
            val path = relativeReferencePath(work, input.path)
            createReferenceInputParents(work, path.parent)
            Files.write(path, input.content, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"))
        }
        val original = Path.of(definition.executablePath)
        val alias = work.resolve(definition.alternateBasename)
        val executable = if (alternate) {
            require(!case.inputs.any { it.path == definition.alternateBasename }) { "alternate executable aliases a case input" }
            Files.createSymbolicLink(alias, original)
            alias
        } else original
        require("TMPDIR" !in case.environment) { "semantic environment may not override the contained temporary directory" }
        val effectiveEnvironment = case.environment + ("TMPDIR" to temporary.toString())
        val processOutput = captureReferenceProcess(listOf(executable.toString()) + case.arguments,
            effectiveEnvironment, work, case.stdin, definition.limits, aggregate)
        requireReferenceArtifact(definition.executableIdentity, executable = true)
        if (alternate) {
            require(Files.isSymbolicLink(alias) && Files.readSymbolicLink(alias) == original) {
                "alternate executable alias changed during execution"
            }
            Files.delete(alias)
        }
        val artifacts = collectReferenceArtifacts(work, case.inputs, definition.limits.maximumArtifactBytes, aggregate,
            definition.limits.maximumAggregateOutputBytes)
        // A successful capture may not silently drop material retained in the private temporary tree.
        val temporaryArtifacts = collectReferenceArtifacts(temporary, emptyList(), definition.limits.maximumArtifactBytes,
            aggregate, definition.limits.maximumAggregateOutputBytes)
        require(temporaryArtifacts.isEmpty()) { "${case.id}: native invocation retained unexpected temporary files" }
        val comparable = JsonObject(mapOf(
            "exitCode" to JsonPrimitive(processOutput.exitCode),
            "stdout" to referenceBlob(processOutput.stdout), "stderr" to referenceBlob(processOutput.stderr),
            "artifacts" to JsonArray(artifacts),
        ))
        val record = JsonObject(mapOf(
            "attempt" to JsonPrimitive(attempt), "invokedAs" to JsonPrimitive(executable.toString()),
            "workingDirectory" to JsonPrimitive(work.toString()),
            "effectiveEnvironment" to referenceEnvironment(effectiveEnvironment),
            "executableSha256" to JsonPrimitive(definition.executableIdentity.sha256),
            "observed" to comparable,
        ))
        return CapturedReferenceInvocation(executable.toString(), processOutput.stdout, processOutput.stderr, comparable, record)
    }
}

private data class CapturedReferenceInvocation(
    val invokedAs: String, val stdout: ByteArray, val stderr: ByteArray,
    val comparable: JsonObject, val record: JsonObject,
)

private data class CapturedReferenceProcess(val exitCode: Int, val stdout: ByteArray, val stderr: ByteArray)

/** Process-group cleanup here is best effort; the outer cgroup owner proves terminal absence. */
private fun captureReferenceProcess(
    arguments: List<String>, environment: Map<String, String>, directory: Path, stdin: ByteArray,
    limits: ReferenceCorpusLimits, aggregate: AtomicLong,
): CapturedReferenceProcess {
    val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(limits.wallClockMillisPerInvocation)
    val readers = Executors.newFixedThreadPool(3) { runnable ->
        Thread(runnable, "reference-corpus-io").apply { isDaemon = true }
    }
    var process: Process? = null
    try {
        process = ProcessBuilder(arguments).directory(directory.toFile()).also { builder ->
            builder.environment().clear()
            builder.environment().putAll(environment)
        }.start()
        val child = process
        val stdout = readers.submit<ByteArray> {
            readReferenceStream(child.inputStream, Math.toIntExact(limits.maximumStdoutBytes), aggregate, limits.maximumAggregateOutputBytes)
        }
        val stderr = readers.submit<ByteArray> {
            readReferenceStream(child.errorStream, Math.toIntExact(limits.maximumStderrBytes), aggregate, limits.maximumAggregateOutputBytes)
        }
        val input = readers.submit {
            try { child.outputStream.use { it.write(stdin) } } catch (_: java.io.IOException) {
                // A child is allowed to close stdin without consuming it. Exit and streams still decide its observation.
            }
        }
        while (true) {
            checkReferenceFuture(stdout)
            checkReferenceFuture(stderr)
            val remaining = referenceRemainingNanos(deadline)
            if (child.waitFor(minOf(remaining, TimeUnit.MILLISECONDS.toNanos(25)), TimeUnit.NANOSECONDS)) break
        }
        val out = stdout.get(referenceRemainingNanos(deadline), TimeUnit.NANOSECONDS)
        val err = stderr.get(referenceRemainingNanos(deadline), TimeUnit.NANOSECONDS)
        input.get(referenceRemainingNanos(deadline), TimeUnit.NANOSECONDS)
        referenceRemainingNanos(deadline)
        val exitCode = child.exitValue()
        // Java does not expose waitpid's exited/signalled discriminator. Never report an
        // ambiguous signal-shaped status as an ordinary exit.
        require(exitCode in 0..127) { "reference native termination cannot be represented unambiguously" }
        return CapturedReferenceProcess(exitCode, out, err)
    } catch (failure: Exception) {
        val actual = if (failure is ExecutionException) failure.cause ?: failure else failure
        throw ReferenceCorpusWorkerException("reference native invocation did not complete within its capture policy", actual)
    } finally {
        process?.let { child ->
            if (child.isAlive) {
                child.descendants().use { stream -> stream.limit(256).toList().asReversed().forEach { it.destroyForcibly() } }
                // Process.destroyForcibly also closes pipes synchronously in the JDK.
                // Signal through ProcessHandle so inherited pipe locks cannot block cleanup.
                child.toHandle().destroyForcibly()
                child.waitFor(1, TimeUnit.SECONDS)
            }
            // A dead direct child may leave pipe descriptors in a surviving descendant. A
            // blocking IO task can hold the stream's monitor, so synchronous close here would
            // turn a bounded capture failure into an unbounded wait. The retained outer owner
            // kills the whole cgroup; these daemon closers are only best-effort local cleanup.
            listOf(child.outputStream, child.inputStream, child.errorStream).forEach { stream ->
                Thread({ runCatching { stream.close() } }, "reference-corpus-close").apply { isDaemon = true }.start()
            }
        }
        readers.shutdownNow()
    }
}

private fun checkReferenceFuture(future: Future<ByteArray>) {
    if (future.isDone) future.get()
}

private fun referenceRemainingNanos(deadline: Long): Long = (deadline - System.nanoTime()).also {
    if (it <= 0L) throw java.util.concurrent.TimeoutException("reference invocation deadline expired")
}

private fun readReferenceStream(input: InputStream, maximum: Int, aggregate: AtomicLong, aggregateMaximum: Long): ByteArray =
    input.use { stream ->
        val captured = ByteArrayOutputStream(minOf(maximum, 8192))
        val buffer = ByteArray(8192)
        while (true) {
            val count = stream.read(buffer)
            if (count < 0) break
            if (count == 0) continue
            if (captured.size().toLong() + count > maximum) referenceWorkerFail("native output stream exceeds policy")
            chargeReferenceOutput(aggregate, count.toLong(), aggregateMaximum)
            captured.write(buffer, 0, count)
        }
        captured.toByteArray()
    }

private fun collectReferenceArtifacts(
    root: Path, inputs: List<ReferenceCorpusInput>, maximum: Long, aggregate: AtomicLong, aggregateMaximum: Long,
): List<JsonObject> {
    val entries = Files.walk(root, MAXIMUM_ARTIFACT_DEPTH + 1).use { stream ->
        stream.limit(MAXIMUM_ARTIFACT_ENTRIES + 1L).toList()
    }
    require(entries.size <= MAXIMUM_ARTIFACT_ENTRIES) { "reference artifact membership exceeds policy" }
    var retainedBytes = 0L
    val original = inputs.associateBy { it.path }
    return entries.filter { it != root }.sortedBy { root.relativize(it).toString() }.mapNotNull { path ->
        val relative = root.relativize(path).toString()
        require(root.relativize(path).nameCount <= MAXIMUM_ARTIFACT_DEPTH) { "reference artifact depth exceeds policy" }
        val attributes = Files.readAttributes(path, BasicFileAttributes::class.java, NOFOLLOW_LINKS)
        if (attributes.isDirectory) {
            null
        } else {
            require(attributes.isRegularFile && !attributes.isSymbolicLink) { "reference artifact is not an ordinary file" }
            val input = original[relative]
            val readMaximum = maxOf(maximum, input?.bytes ?: 0L)
            require(attributes.size() in 0L..readMaximum) { "reference artifact exceeds policy" }
            val data = readStableReferenceFile(path, Math.toIntExact(readMaximum), allowEmpty = true)
            if (input != null && data.contentEquals(input.content)) null else {
                retainedBytes = Math.addExact(retainedBytes, data.size.toLong())
                require(retainedBytes <= maximum) { "reference artifacts exceed their aggregate invocation bound" }
                chargeReferenceOutput(aggregate, data.size.toLong(), aggregateMaximum)
                JsonObject(referenceBlob(data) + ("path" to JsonPrimitive(relative)))
            }
        }
    }
}

private fun chargeReferenceOutput(counter: AtomicLong, bytes: Long, maximum: Long) {
    val total = counter.addAndGet(bytes)
    if (total > maximum || total < 0L) referenceWorkerFail("reference batch output exceeds aggregate policy")
}

private fun requireReferenceBatchArtifacts(definition: ReferenceCorpusDefinition, batchId: String) {
    val included = definition.artifactRolesForBatch(batchId)
    for ((role, identity) in definition.artifacts) {
        if (role in included) requireReferenceArtifact(identity, role == definition.executableRole)
        else require(Files.notExists(Path.of(identity.guestPath), NOFOLLOW_LINKS)) {
            "reference batch exposes an excluded artifact role: $role"
        }
    }
}

private fun requireReferenceArtifact(identity: ReferenceCorpusArtifactIdentity, executable: Boolean) {
    val path = Path.of(identity.guestPath)
    requireAbsoluteReferencePath(path)
    if (executable) require(Files.isExecutable(path)) { "reference executable is not executable" }
    val bytes = readStableReferenceFile(path, Math.toIntExact(identity.bytes))
    require(bytes.size.toLong() == identity.bytes && OracleArtifacts.sha256(bytes) == identity.sha256) {
        "reference artifact differs from its fixed identity"
    }
}

private fun readStableReferenceFile(path: Path, maximum: Int, allowEmpty: Boolean = false): ByteArray {
    requireAbsoluteReferencePath(path)
    require(path.toRealPath() == path) { "reference file contains path indirection" }
    val before = Files.readAttributes(path, BasicFileAttributes::class.java, NOFOLLOW_LINKS)
    require(before.isRegularFile && before.size() in (if (allowEmpty) 0L else 1L)..maximum.toLong()) {
        "reference file exceeds its regular-file size policy"
    }
    val bytes = Files.newInputStream(path, NOFOLLOW_LINKS).use { it.readNBytes(maximum + 1) }
    val after = Files.readAttributes(path, BasicFileAttributes::class.java, NOFOLLOW_LINKS)
    require(before.fileKey() != null && before.fileKey() == after.fileKey() && before.size() == after.size() &&
        before.lastModifiedTime() == after.lastModifiedTime() && bytes.size.toLong() == before.size()) {
        "reference file changed during read"
    }
    return bytes
}

private fun referenceBlob(bytes: ByteArray): JsonObject = JsonObject(mapOf(
    "bytes" to JsonPrimitive(bytes.size), "sha256" to JsonPrimitive(OracleArtifacts.sha256(bytes)),
    "base64" to JsonPrimitive(Base64.getEncoder().encodeToString(bytes)),
))

private fun referenceEnvironment(environment: Map<String, String>): JsonObject =
    JsonObject(environment.mapValues { JsonPrimitive(it.value) })

private fun requireAbsoluteReferencePath(path: Path) {
    require(path.isAbsolute && path.normalize() == path && path != Path.of("/")) { "reference path is not normalized and absolute" }
}

private fun requirePrivateReferenceDirectory(path: Path) {
    requireAbsoluteReferencePath(path)
    require(path.toRealPath() == path && Files.isDirectory(path, NOFOLLOW_LINKS)) { "reference directory contains indirection" }
    require(Files.getPosixFilePermissions(path) == PosixFilePermissions.fromString("rwx------")) {
        "reference directory is not owner-only"
    }
}

private fun createPrivateReferenceDirectory(path: Path) {
    Files.createDirectory(path, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
    requirePrivateReferenceDirectory(path)
}

private fun relativeReferencePath(root: Path, relative: String): Path {
    val path = Path.of(relative)
    require(relative.isNotEmpty() && !path.isAbsolute && path.normalize() == path &&
        path.none { it.toString() == "." || it.toString() == ".." } && path.nameCount <= MAXIMUM_ARTIFACT_DEPTH) {
        "reference input path escapes its workspace"
    }
    return root.resolve(path).also { require(it.startsWith(root) && it != root) }
}

private fun createReferenceInputParents(root: Path, parent: Path) {
    var current = root
    for (component in root.relativize(parent)) {
        current = current.resolve(component)
        if (!Files.exists(current, NOFOLLOW_LINKS)) createPrivateReferenceDirectory(current)
        requirePrivateReferenceDirectory(current)
    }
}

private fun referenceWorkerFail(message: String): Nothing = throw ReferenceCorpusWorkerException(message)

private val REFERENCE_SHA256 = Regex("[a-f0-9]{64}")
private const val MAXIMUM_PROFILE_BYTES = 512 * 1024
private const val MAXIMUM_REFERENCE_CASES = 256
private const val MAXIMUM_CAPTURE_BYTES = 16 * 1024 * 1024
private const val MAXIMUM_ARTIFACT_ENTRIES = 256
private const val MAXIMUM_ARTIFACT_DEPTH = 16
private val REFERENCE_REQUEST_LIMITS = StrictJsonLimits(maximumInputBytes = 16 * 1024, maximumCanonicalBytes = 16 * 1024,
    maximumStringBytes = 4096, maximumTotalStringBytes = 12 * 1024, maximumNodes = 128, maximumDepth = 4)
private val REFERENCE_REPORT_LIMITS = StrictJsonLimits(maximumInputBytes = ReferenceCorpusWorker.MAXIMUM_OBSERVATION_BYTES,
    maximumCanonicalBytes = ReferenceCorpusWorker.MAXIMUM_OBSERVATION_BYTES, maximumStringBytes = 8 * 1024 * 1024,
    maximumTotalStringBytes = 16 * 1024 * 1024, maximumNodes = 100_000, maximumDepth = 24)
